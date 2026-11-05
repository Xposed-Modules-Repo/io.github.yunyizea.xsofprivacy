package io.github.yunyizea.xsofprivacy;

import java.util.*;
import io.github.yunyizea.xsofprivacy.DexIndex.*;
import io.github.yunyizea.xsofprivacy.CompatibilityResolver.*;
import static io.github.yunyizea.xsofprivacy.ResolverTest.*;

/** Real-APK regression checks for the two optional scopes; no device execution. */
public final class ExtendedResolverTest {
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

    public static void main(String[] args) throws Exception {
        DexIndex guard = DexIndex.scan(Collections.singletonList(args[0]));
        DexIndex helper = DexIndex.scan(Collections.singletonList(args[1]));
        profile(ExtendedResolver.GUARD, guard, 1);
        profile(ExtendedResolver.HELPER, helper, 10);
        System.out.println("PASS all 11 extended targets and result policies equal adaptive profiles");
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
    }
}
