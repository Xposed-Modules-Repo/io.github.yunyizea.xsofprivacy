package io.github.yunyizea.xsofprivacy;

import org.junit.Test;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.Assert.*;

public final class InterceptionLogTest {
    private final AtomicLong clock = new AtomicLong();
    private final AtomicBoolean setting = new AtomicBoolean();
    private final AtomicInteger reads = new AtomicInteger();
    private final List<String> lines = new ArrayList<>();
    private final InterceptionLog log = new InterceptionLog("[XsofPrivacy][test] package=test pid=123",
            () -> { reads.incrementAndGet(); return setting.get(); }, clock::get,
            () -> 1793836800123L, lines::add);

    private void record(long hit) {
        log.record("storage.screenshot", "Ldb;->insert(Lmodel;)V", "void", hit,
                456, 1000, "not_applicable", "not_applicable");
    }

    @Test public void disabledByDefaultAndReadsAreBoundedAcrossEvents() {
        record(1);
        record(2);
        clock.set(999);
        record(3);
        assertTrue(lines.isEmpty());
        assertEquals(1, reads.get());
    }

    @Test public void togglesBothWaysWithoutRecreatingLogger() {
        record(1);
        setting.set(true);
        clock.set(1000);
        record(2);
        record(3);
        assertEquals(2, lines.size());
        assertTrue(lines.get(0).contains("hit=2"));
        assertTrue(lines.get(1).contains("hit=3"));
        setting.set(false);
        clock.set(2000);
        record(4);
        assertEquals(2, lines.size());
        assertEquals(3, reads.get());
    }

    @Test public void everyEnabledHitContainsInterceptionMetadata() {
        setting.set(true);
        record(1);
        record(2);
        assertEquals(2, lines.size());
        String line = lines.get(1);
        for (String field : new String[]{"BLOCKED time=", "package=test", "pid=123",
                "tid=456", "callingUid=1000", "group=storage.screenshot",
                "method=Ldb;->insert(Lmodel;)V", "original=skipped result=void", "hit=2"})
            assertTrue(field, line.contains(field));
        assertTrue(line.contains("2026-11-05T00:00:00.123Z"));
    }

    @Test public void recordsFailureAndServiceOutcomesWithoutClaimingServiceStopped() {
        setting.set(true);
        log.record("api.current", "api", "void", 1, 1, 2,
                "failed:InvocationTargetException", "not_applicable");
        log.record("guard.ai_detection", "service", "START_NOT_STICKY", 1, 1, 2,
                "not_applicable", "requested");
        log.record("helper.encrypted_post", "post", "false", 1, 1, 2,
                "not_applicable", "not_applicable");
        assertTrue(lines.get(0).contains("callback=failed:InvocationTargetException"));
        assertTrue(lines.get(1).contains("serviceStop=requested"));
        assertTrue(lines.get(2).contains("result=false"));
    }

    @Test public void readFailureDisablesDetailsAndRecoversOnNextPoll() {
        AtomicInteger calls = new AtomicInteger();
        InterceptionLog failing = new InterceptionLog("test", () -> {
            if (calls.incrementAndGet() == 2) throw new SecurityException("private message");
            return true;
        }, clock::get, () -> 0, lines::add);
        failing.record("g", "m", "void", 1, 1, 1, "none", "none");
        clock.set(1000);
        failing.record("g", "m", "void", 2, 1, 1, "none", "none");
        failing.record("g", "m", "void", 3, 1, 1, "none", "none");
        assertEquals(2, lines.size());
        assertTrue(lines.get(1).contains("DETAIL_SETTINGS_UNAVAILABLE type=SecurityException"));
        assertEquals(2, calls.get());
        clock.set(2000);
        failing.record("g", "m", "void", 4, 1, 1, "none", "none");
        assertEquals(4, lines.size());
        assertTrue(lines.get(2).contains("DETAIL_SETTINGS_RECOVERED"));
        assertFalse(String.join("", lines).contains("private message"));
    }

    @Test public void outputFailureNeverEscapesToHook() {
        InterceptionLog failing = new InterceptionLog("test", () -> true, clock::get,
                () -> 0, line -> { throw new IllegalStateException("logger unavailable"); });
        failing.record("g", "m", "void", 1, 1, 1, "none", "none");
    }

    @Test public void concurrentCallsShareOneSettingsRead() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AtomicInteger events = new AtomicInteger();
        InterceptionLog concurrent = new InterceptionLog("test", () -> {
            calls.incrementAndGet(); return true;
        }, () -> 0, () -> 0, line -> events.incrementAndGet());
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            Thread thread = new Thread(() -> concurrent.record("g", "m", "void", 1,
                    1, 1, "none", "none"));
            threads.add(thread);
            thread.start();
        }
        for (Thread thread : threads) thread.join();
        assertEquals(1, calls.get());
        assertEquals(16, events.get());
    }
}
