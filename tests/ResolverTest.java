package io.github.yunyizea.xsofprivacy;

import java.util.*;
import io.github.yunyizea.xsofprivacy.DexIndex.*;
import io.github.yunyizea.xsofprivacy.CompatibilityResolver.*;

/** Host tests of identification policy; not Android/LSPosed runtime tests. */
public final class ResolverTest {
    static void check(boolean condition,String message) { if(!condition)throw new AssertionError(message); }
    static Set<Id> targets(List<Group> groups) {
        Set<Id> out=new HashSet<>();
        for(Group g:groups) {
            check(g.skip==null,g.name+" skipped: "+g.skip);
            for(Target t:g.targets)check(out.add(t.method),"duplicate target");
        }
        return out;
    }
    static String renameType(String s) {
        if(s==null)return null;
        if(!s.startsWith("L")||s.startsWith("Ljava/")||s.startsWith("Landroid/"))return s;
        return "Lfixture/C"+Integer.toUnsignedString(s.hashCode(),16)+";";
    }
    static Id rename(Id id) {
        List<String> args=new ArrayList<>();for(String a:id.args)args.add(renameType(a));
        String name=id.name;
        if(!renameType(id.owner).equals(id.owner)&&!name.startsWith("<")
                &&!Arrays.asList("onCreate","onDestroy","insert","query","delete","update","getType").contains(name))
            name="m"+Integer.toUnsignedString(id.toString().hashCode(),16);
        return new Id(renameType(id.owner),name,renameType(id.result),args);
    }
    static DexIndex renamed(DexIndex index) {
        DexIndex out=new DexIndex();
        for(Clazz c:index.classes.values()) {
            Clazz copy=new Clazz(renameType(c.type),renameType(c.parent));
            for(Node n:c.nodes) {
                Node node=new Node(rename(n.id),n.flags);
                node.strings.addAll(n.strings);node.numbers.addAll(n.numbers);
                for(Id call:n.calls)node.calls.add(rename(call));
                copy.nodes.add(node);
            }
            out.add(copy);
        }
        return out;
    }
    static Group get(List<Group> groups,String name) {
        for(Group g:groups)if(g.name.equals(name))return g;
        throw new AssertionError("Missing group "+name);
    }
    public static void main(String[] args) throws Exception {
        long start=System.nanoTime();
        DexIndex index=DexIndex.scan(Collections.singletonList(args[0]));
        List<Group> groups=CompatibilityResolver.discover(index);
        for(Group g:groups)System.out.println(g.name+": "+(g.skip==null?g.targets.size():"SKIP "+g.skip));
        Set<Id> actual=targets(groups),known=targets(CompatibilityResolver.known());
        check(actual.size()==28,"Expected 28 adaptive targets");
        check(actual.equals(known),"Adaptive and exact profiles differ");
        for(Group g:groups)for(Target t:g.targets)if(t.callback!=null)
            check(t.callback.name.equals("G2"),"Wrong original callback");
        System.out.println("PASS real APK forced-adaptive profile equals all 28 known targets");

        DexIndex renamed=renamed(index);
        Set<Id> expected=new HashSet<>();for(Id id:actual)expected.add(rename(id));
        List<Group> renamedGroups=CompatibilityResolver.discover(renamed);
        check(targets(renamedGroups).equals(expected),"Renamed fixture differs");
        for(Group g:renamedGroups)for(Target t:g.targets)if(t.callback!=null)
            check(!t.callback.name.equals("G2"),"Callback name was hardcoded");
        System.out.println("PASS renamed class/method/callback metadata fixture");

        Group screenshot=get(groups,"storage.screenshot");
        Node original=index.methods.get(screenshot.targets.get(0).method);
        Node duplicate=new Node(new Id(original.id.owner,"ambiguousScreenshot","V",original.id.args),original.flags);
        duplicate.strings.addAll(original.strings);duplicate.calls.addAll(original.calls);
        index.classes.get(original.id.owner).nodes.add(duplicate);index.methods.put(duplicate.id,duplicate);
        List<Group> ambiguous=CompatibilityResolver.discover(index);
        check(get(ambiguous,"storage.screenshot").skip!=null,"Ambiguous writer accepted");
        check(get(ambiguous,"storage.install_app").skip==null,"Unrelated group disabled");
        index.classes.get(original.id.owner).nodes.remove(duplicate);index.methods.remove(duplicate.id);
        System.out.println("PASS duplicate screenshot candidate skipped, unrelated group retained");

        Node listener=null;
        for(Node n:index.methods.values())if(n.text("miui.intent.TAKE_SCREENSHOT")&&n.isVoid(0))listener=n;
        check(listener!=null,"missing fixture listener");
        listener.strings.remove("miui.intent.TAKE_SCREENSHOT");
        List<Group> missing=CompatibilityResolver.discover(index);
        check(get(missing,"listeners").skip!=null,"Incomplete listener group accepted");
        check(get(missing,"storage.screenshot").skip==null,"Independent storage group disabled");
        listener.strings.add("miui.intent.TAKE_SCREENSHOT");
        System.out.println("PASS missing registration skips entire paired listener group");

        Node helper=null;
        for(Node n:index.methods.values())for(Id call:n.calls)
            if(call.owner.equals("Lcom/xiaomi/security/xsof/IMiSafetyDetectCallback;")
                    &&call.args.equals(Arrays.asList("Ljava/lang/String;","I")))helper=n;
        check(helper!=null,"Missing callback helper");
        Set<Id> calls=new HashSet<>(helper.calls);helper.calls.clear();
        List<Group> callbackMissing=CompatibilityResolver.discover(index);
        for(String kind:new String[]{"current","past","duration","score"})
            check(get(callbackMissing,"api."+kind).skip!=null,"Unknown callback accepted");
        helper.calls.addAll(calls);
        System.out.println("PASS unknown callback skips all affected APIs");

        Node score=index.methods.get(get(groups,"api.score").targets.get(0).method);
        score.numbers.remove(1017L);
        List<Group> changedCode=CompatibilityResolver.discover(index);
        check(get(changedCode,"api.score").skip!=null,"Changed rejection contract accepted");
        check(get(changedCode,"api.current").skip==null,"Unrelated API disabled");
        score.numbers.add(1017L);
        System.out.println("PASS changed rejection-code evidence skips only affected API");
        check(targets(CompatibilityResolver.discover(index)).equals(known),"Fixture mutations not restored");
        System.out.println("ALL PASS elapsedMs="+((System.nanoTime()-start)/1000000));
    }
}
