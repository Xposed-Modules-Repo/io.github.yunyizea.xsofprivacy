package io.github.yunyizea.xsofprivacy;

import java.util.*;
import io.github.yunyizea.xsofprivacy.DexIndex.*;
import io.github.yunyizea.xsofprivacy.CompatibilityResolver.*;
import static io.github.yunyizea.xsofprivacy.ResolverTest.*;

/** Real-APK regression checks for the two optional scopes; no device execution. */
public final class ExtendedResolverTest {
    static DexIndex copy(DexIndex source) {
        DexIndex out = new DexIndex();
        for (Clazz c : source.classes.values()) {
            Clazz clone = new Clazz(c.type, c.parent);
            for (Node n : c.nodes) {
                Node node = new Node(n.id, n.flags);
                node.strings.addAll(n.strings);
                node.numbers.addAll(n.numbers);
                node.calls.addAll(n.calls);
                clone.nodes.add(node);
            }
            out.add(clone);
        }
        return out;
    }

    static Group postGroup(DexIndex index) {
        return get(ExtendedResolver.discover(ExtendedResolver.HELPER, index), "helper.encrypted_post");
    }

    /** Synthetic metadata for the reported 4.0.0 shape; not a substitute for that APK. */
    static DexIndex pairedFixture(DexIndex source) {
        DexIndex fixture = copy(source);
        Node encrypted = fixture.methods.get(postGroup(fixture).targets.get(0).method);
        encrypted.strings.remove("register success!");
        encrypted.strings.add("HTTPS register success!");
        Node fallback = new Node(new Id(encrypted.id.owner, "fixtureFallback", "Z",
                "Ljava/lang/String;", "[B"), encrypted.flags);
        fallback.calls.addAll(encrypted.calls);
        fixture.classes.get(encrypted.id.owner).nodes.add(fallback);
        fixture.methods.put(fallback.id, fallback);
        Clazz caller = new Clazz("Lfixture/Telemetry;", "Ljava/lang/Object;");
        Node upload = new Node(new Id(caller.type, "upload", "V"), 0);
        upload.calls.add(encrypted.id);
        upload.calls.add(fallback.id);
        caller.nodes.add(upload);
        check(DexIndex.telemetryPairCaller(caller), "Unanchored caller would be dropped by DEX scanning");
        fixture.add(caller);
        return fixture;
    }

    static void senderFixtures(DexIndex helper) {
        DexIndex paired = pairedFixture(helper);
        Group pair = postGroup(paired);
        check(pair.skip == null && pair.targets.size() == 2, "Linked sender pair not recognized");
        for (Target target : pair.targets) check(target.mode == Target.FALSE, "Wrong pair result policy");

        Group renamed = postGroup(renamed(paired));
        check(renamed.skip == null && renamed.targets.size() == 2, "Renamed sender pair rejected");
        Set<Id> expected = new HashSet<>();
        for (Target target : pair.targets) expected.add(rename(target.method));
        for (Target target : renamed.targets) check(expected.remove(target.method), "Wrong renamed sender");
        check(expected.isEmpty(), "Missing renamed sender");

        Node encrypted = paired.methods.get(pair.targets.get(0).method);
        encrypted.strings.remove("HTTPS register success!");
        encrypted.strings.add("future success log");
        check(postGroup(paired).skip == null, "Pair depends on an exact success log");
        encrypted.strings.remove("future success log");
        encrypted.strings.add("HTTPS register success!");

        Node fallback = paired.methods.get(pair.targets.get(1).method);
        Set<Id> calls = new HashSet<>(fallback.calls);
        fallback.calls.removeIf(id -> id.name.equals("getOutputStream"));
        check(postGroup(paired).skip != null, "Partial newer sender pair accepted as legacy");
        fallback.calls.addAll(calls);
        Node caller = paired.methods.get(new Id("Lfixture/Telemetry;", "upload", "V"));
        caller.calls.remove(fallback.id);
        check(!DexIndex.telemetryPairCaller(paired.classes.get(caller.id.owner)),
                "Unrelated caller incorrectly retained as pair evidence");
        check(postGroup(paired).skip != null, "Unlinked sender accepted as fallback");
        caller.calls.add(fallback.id);

        Node duplicate = new Node(new Id(fallback.id.owner, "secondFallback", "Z", fallback.id.args), fallback.flags);
        duplicate.calls.addAll(fallback.calls);
        paired.classes.get(duplicate.id.owner).nodes.add(duplicate);
        paired.methods.put(duplicate.id, duplicate);
        check(postGroup(paired).skip != null, "Ambiguous sender set accepted");

        DexIndex legacy = copy(helper);
        Node oldSender = legacy.methods.get(postGroup(legacy).targets.get(0).method);
        oldSender.strings.remove("register success!");
        check(postGroup(legacy).skip != null, "Unverified single sender accepted");
        check(get(ExtendedResolver.discover(ExtendedResolver.HELPER, legacy), "helper.app_usage").skip == null,
                "Independent group lost after sender skip");
        System.out.println("PASS synthetic linked pair, renamed pair, changed logs, incomplete/unlinked/ambiguous senders");
    }

    static void profile(String pkg, DexIndex index, int count) {
        List<Group> found = ExtendedResolver.discover(pkg, index);
        List<Group> known = ExtendedResolver.known(pkg);
        check(targets(found).equals(targets(known)), "Extended adaptive profile differs: " + pkg);
        check(targets(found).size() == count, "Wrong extended target count: " + pkg);
        for (Group group : known) {
            Group actual = get(found, group.name);
            for (int i = 0; i < group.targets.size(); i++) {
                Target expected = group.targets.get(i), target = actual.targets.get(i);
                check(expected.mode == target.mode, "Wrong result policy: " + group.name);
                check(index.methods.containsKey(target.method), "Missing method in APK");
            }
        }
    }

    static void realHelper400(String path) throws Exception {
        DexIndex index = DexIndex.scan(Collections.singletonList(path));
        List<Group> groups = ExtendedResolver.discover(ExtendedResolver.HELPER, index);
        check(groups.size() == 10 && targets(groups).size() == 11, "Wrong real 4.0.0 group/target count");
        Group post = get(groups, "helper.encrypted_post");
        Id encrypted = new Id("Lg1/f;", "g", "Z", "Ljava/lang/String;", "[B", "[B");
        Id fallback = new Id("Lg1/f;", "f", "Z", "Ljava/lang/String;", "[B");
        Set<Id> expected = new HashSet<>(Arrays.asList(encrypted, fallback));
        for (Target target : post.targets) {
            check(expected.remove(target.method), "Unexpected real sender: " + target.method);
            check(target.mode == Target.FALSE && target.callback == null, "Wrong real sender policy");
        }
        check(expected.isEmpty(), "Real sender missing");
        for (Group known : ExtendedResolver.known(ExtendedResolver.HELPER)) {
            if (known.name.equals("helper.encrypted_post")) continue;
            Group actual = get(groups, known.name);
            check(actual.targets.size() == known.targets.size(), "Wrong group size: " + known.name);
            for (int i = 0; i < known.targets.size(); i++) {
                check(actual.targets.get(i).method.equals(known.targets.get(i).method), "Changed target: " + known.name);
                check(actual.targets.get(i).mode == known.targets.get(i).mode, "Changed policy: " + known.name);
            }
        }
        Node caller = index.methods.get(new Id("Le1/g;", "a", "Z", "Le1/b;"));
        check(caller != null && caller.calls.contains(encrypted) && caller.calls.contains(fallback),
                "Real common caller was not retained by DEX scanning");
        Group renamed = postGroup(renamed(index));
        check(renamed.skip == null && renamed.targets.size() == 2, "Renamed real pair rejected");

        Node plain = index.methods.get(fallback);
        Set<Id> plainCalls = new HashSet<>(plain.calls);
        plain.calls.removeIf(id -> id.name.equals("getOutputStream"));
        check(postGroup(index).skip != null, "Partially recognized real pair accepted");
        plain.calls.addAll(plainCalls);
        caller.calls.remove(fallback);
        check(postGroup(index).skip != null, "Real pair accepted without common caller");
        caller.calls.add(fallback);
        Node duplicate = new Node(new Id(fallback.owner, "ambiguousRealFallback", "Z", fallback.args), plain.flags);
        duplicate.calls.addAll(plain.calls);
        index.classes.get(fallback.owner).nodes.add(duplicate);
        index.methods.put(duplicate.id, duplicate);
        check(postGroup(index).skip != null, "Ambiguous real sender set accepted");
        index.classes.get(fallback.owner).nodes.remove(duplicate);
        index.methods.remove(duplicate.id);
        check(targets(ExtendedResolver.discover(ExtendedResolver.HELPER, index)).size() == 11,
                "Real APK fixture mutations not restored");
        System.out.println("PASS real SystemHelper 4.0.0: 10 groups, 11 targets, g/f FALSE policies, common caller retained");
        System.out.println("PASS real 4.0.0 metadata: rename, incomplete sender, missing caller and ambiguity regressions");
    }

    public static void main(String[] args) throws Exception {
        DexIndex guard = DexIndex.scan(Collections.singletonList(args[0]));
        DexIndex helper = DexIndex.scan(Collections.singletonList(args[1]));
        profile(ExtendedResolver.GUARD, guard, 1);
        profile(ExtendedResolver.HELPER, helper, 10);
        System.out.println("PASS all 11 extended targets and result policies equal adaptive profiles");
        senderFixtures(helper);
        check(ExtendedResolver.discover("other.package", helper).isEmpty(), "Wrong package accepted");
        check(get(ExtendedResolver.discover(ExtendedResolver.GUARD, helper), "guard.ai_detection").skip != null,
                "Wrong APK accepted");

        List<Group> groups = ExtendedResolver.discover(ExtendedResolver.HELPER, helper);
        Node gate = helper.methods.get(get(groups, "helper.policy_gate").targets.get(0).method);
        gate.strings.remove("operator_service_improve_plan");
        List<Group> missing = ExtendedResolver.discover(ExtendedResolver.HELPER, helper);
        check(get(missing, "helper.policy_gate").skip != null, "Missing consent anchor accepted");
        check(get(missing, "helper.encrypted_post").skip == null, "Independent POST group lost");
        gate.strings.add("operator_service_improve_plan");

        Node post = helper.methods.get(get(groups, "helper.encrypted_post").targets.get(0).method);
        Node duplicate = new Node(new Id(post.id.owner, "ambiguousPost", post.id.result, post.id.args), post.flags);
        duplicate.strings.addAll(post.strings);
        duplicate.calls.addAll(post.calls);
        helper.classes.get(post.id.owner).nodes.add(duplicate);
        helper.methods.put(duplicate.id, duplicate);
        check(get(ExtendedResolver.discover(ExtendedResolver.HELPER, helper), "helper.encrypted_post").skip != null,
                "Ambiguous POST accepted");
        helper.classes.get(post.id.owner).nodes.remove(duplicate);
        helper.methods.remove(duplicate.id);

        Node service = guard.methods.get(ExtendedResolver.known(ExtendedResolver.GUARD).get(0).targets.get(0).method);
        Set<Id> calls = new HashSet<>(service.calls);
        service.calls.removeIf(id -> id.owner.equals("Landroid/app/Service;") && id.name.equals("startForeground"));
        check(get(ExtendedResolver.discover(ExtendedResolver.GUARD, guard), "guard.ai_detection").skip != null,
                "Missing foreground-service evidence accepted");
        service.calls.addAll(calls);
        profile(ExtendedResolver.GUARD, guard, 1);
        profile(ExtendedResolver.HELPER, helper, 10);
        System.out.println("PASS wrong package/APK, missing consent/service evidence and ambiguous POST skipped");
        if (args.length == 3) realHelper400(args[2]);
    }
}
