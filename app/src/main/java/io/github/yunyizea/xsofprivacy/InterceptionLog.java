package io.github.yunyizea.xsofprivacy;

import java.time.Instant;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** Per-process, bounded settings polling. Logging failures must never undo an interception. */
final class InterceptionLog {
    private final BooleanSupplier readEnabled;
    private final LongSupplier elapsedMillis;
    private final LongSupplier wallMillis;
    private final Consumer<String> output;
    private final String context;
    private boolean enabled;
    private long checkedAt;
    private boolean checked;
    private boolean readFailed;

    InterceptionLog(String context, BooleanSupplier readEnabled, LongSupplier elapsedMillis,
                    LongSupplier wallMillis, Consumer<String> output) {
        this.context = context;
        this.readEnabled = readEnabled;
        this.elapsedMillis = elapsedMillis;
        this.wallMillis = wallMillis;
        this.output = output;
    }

    private synchronized boolean enabled() {
        long now = elapsedMillis.getAsLong();
        if (!checked || now - checkedAt >= 1000) {
            // Mark before IPC, so a failing read is also limited to once per second.
            checkedAt = now;
            checked = true;
            enabled = false;
            try {
                enabled = readEnabled.getAsBoolean();
                if (readFailed) {
                    readFailed = false;
                    output.accept(context + " DETAIL_SETTINGS_RECOVERED");
                }
            } catch (Throwable failure) {
                if (!readFailed) {
                    readFailed = true;
                    output.accept(context + " DETAIL_SETTINGS_UNAVAILABLE type="
                            + failure.getClass().getSimpleName());
                }
            }
        }
        return enabled;
    }

    void record(String group, String method, String result, long hit,
                int tid, int callingUid, String callback, String serviceStop) {
        try {
            if (!enabled()) return;
            output.accept(context + " BLOCKED time=" + Instant.ofEpochMilli(wallMillis.getAsLong())
                    + " tid=" + tid + " callingUid=" + callingUid
                    + " group=" + group + " method=" + method
                    + " hit=" + hit + " original=skipped result=" + result
                    + " callback=" + callback + " serviceStop=" + serviceStop);
        } catch (Throwable ignored) {
            // No arguments, exception messages, or user data are sent to a fallback logger.
        }
    }
}
