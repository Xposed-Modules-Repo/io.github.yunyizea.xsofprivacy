package io.github.yunyizea.xsofprivacy;

import java.util.*;
import java.util.function.Predicate;
import io.github.yunyizea.xsofprivacy.DexIndex.*;

/** Conservative semantic matching; missing/ambiguous groups are never guessed. */
public final class CompatibilityResolver {
    static final String CTX="Landroid/content/Context;", STR="Ljava/lang/String;";
    static final String SQL="Landroid/database/sqlite/SQLiteDatabase;";
    static final String VALUES="Landroid/content/ContentValues;";
    public static final class Target {
        public final Id method, callback;
        public Target(Id method) { this(method,null); }
        public Target(Id method,Id callback) { this.method=method;this.callback=callback; }
    }
    public static final class Group {
        public final String name;
        public final List<Target> targets=new ArrayList<>();
        public String skip;
        Group(String name) { this.name=name; }
    }
    static Node one(Collection<Node> nodes,Predicate<Node> test,String label) {
        Node found=null;int count=0;
        for(Node n:nodes)if(test.test(n)) { found=n;count++; }
        if(count!=1)throw new IllegalArgumentException(label+": candidates="+count);
        return found;
    }
    static Clazz clazz(DexIndex index,Predicate<Clazz> test,String label) {
        Clazz found=null;int count=0;
        for(Clazz c:index.classes.values())if(test.test(c)) { found=c;count++; }
        if(count!=1)throw new IllegalArgumentException(label+": classes="+count);
        return found;
    }
    interface Match { void match(Group group); }
    static void group(List<Group> groups,String name,Match match) {
        Group g=new Group(name);groups.add(g);
        try { match.match(g);if(g.targets.isEmpty())throw new IllegalArgumentException("empty group"); }
        catch(IllegalArgumentException e) { g.targets.clear();g.skip=e.getMessage(); }
    }
    static void add(Group g,Node n) { g.targets.add(new Target(n.id)); }
    static boolean args(Node n,String... args) { return n.isVoid(args.length)&&n.id.args.equals(Arrays.asList(args)); }

    public static List<Group> discover(DexIndex index) {
        List<Group> groups=new ArrayList<>();
        group(groups,"listeners",g->listeners(index,g));
        String[] tables={"airplane_mode","install_app","call_forwarding","screen_share",
                "screenshot","fraud_phone","fraud_url","voip_record"};
        for(String table:tables)group(groups,"storage."+table,g->storage(index,g,table));
        group(groups,"provider.ingress",g->provider(index,g));
        String[] kinds={"current","past","duration","score"};
        for(int i=0;i<kinds.length;i++) {
            final int kind=i;
            group(groups,"api."+kinds[i],g->api(index,g,kinds[kind],kind));
        }
        return groups;
    }
    static Clazz database(DexIndex index) {
        return clazz(index,c->"Landroid/database/sqlite/SQLiteOpenHelper;".equals(c.parent)
                &&c.text("fraud_detection_data.db")&&c.text("/securitycenter/")
                &&c.text("screenshot")&&c.text("install_app"),"database");
    }
    static void storage(DexIndex index,Group g,String table) {
        Clazz db=database(index);
        Node insert=one(db.nodes,n->n.isVoid(1)&&n.id.args.get(0).startsWith("L")
                &&n.text(table)&&n.calls(SQL,"insert"),table+" insert");
        add(g,insert);
        int arity="voip_record".equals(table)?2:1;
        if(Arrays.asList("screen_share","fraud_phone","voip_record").contains(table)) {
            Node update=one(db.nodes,n->n.isVoid(arity)&&n.text(table)&&n.calls(SQL,"update"),table+" update");
            if("fraud_phone".equals(table)&&!args(update,STR))throw new IllegalArgumentException("phone update shape");
            if(!"fraud_phone".equals(table)&&!update.id.args.get(0).equals(insert.id.args.get(0)))
                throw new IllegalArgumentException("insert/update model mismatch");
            if(arity==2&&!"I".equals(update.id.args.get(1)))throw new IllegalArgumentException("update type mismatch");
            add(g,update);
        }
    }
    static void provider(DexIndex index,Group g) {
        Clazz db=database(index);
        Clazz p=clazz(index,c->"Landroid/content/ContentProvider;".equals(c.parent)
                &&c.text("com.xiaomi.security.xsof.FraudDetectionProvider")
                &&c.text("install_app")&&c.text("call_forwarding")&&c.text("fraud_url"),"provider");
        Node insert=one(p.nodes,n->n.id.name.equals("insert")
                &&n.id.args.equals(Arrays.asList("Landroid/net/Uri;",VALUES))
                &&n.id.result.equals("Landroid/net/Uri;"),"provider insert");
        for(Node n:p.nodes)if(args(n,VALUES)&&insert.calls.contains(n.id)) {
            boolean writes=false;
            for(Id call:n.calls)if(call.owner.equals(db.type)&&"V".equals(call.result))writes=true;
            if(writes)add(g,n);
        }
        if(g.targets.size()!=3)throw new IllegalArgumentException("provider writer count="+g.targets.size());
    }
    static void listeners(DexIndex index,Group g) {
        Clazz s=clazz(index,c->"Landroid/app/Service;".equals(c.parent)
                &&c.text("miui.intent.TAKE_SCREENSHOT")&&c.text("android.intent.action.PHONE_STATE")
                &&c.text("android.intent.action.SIM_STATE_CHANGED"),"collector service");
        Node create=one(s.nodes,n->n.id.name.equals("onCreate")&&args(n),"onCreate");
        Node destroy=one(s.nodes,n->n.id.name.equals("onDestroy")&&args(n),"onDestroy");
        String[] events={"miui.intent.TAKE_SCREENSHOT","android.intent.action.SIM_STATE_CHANGED",
                "android.intent.action.AIRPLANE_MODE","android.intent.action.PHONE_STATE","action_update_sc_network_allow"};
        for(String event:events) {
            Node n=one(s.nodes,m->args(m)&&m.text(event)&&create.calls.contains(m.id)
                    &&m.calls("Landroid/content/IntentFilter;","<init>"),event);
            add(g,n);
        }
        add(g,one(s.nodes,n->args(n)&&n.text("MIUI:10042")&&n.text("appops")
                &&create.calls.contains(n.id),"AppOps registration"));
        add(g,one(s.nodes,n->args(n,CTX)&&n.text("getCallForwarding")
                &&n.text("android.telephony.TelephonyManager$CallForwardingInfoCallback")
                &&create.calls.contains(n.id),"call forwarding"));
        Node cleanup=one(s.nodes,n->args(n)&&n.calls(CTX,"unregisterReceiver")
                &&destroy.calls.contains(n.id),"listener cleanup");
        add(g,cleanup);
        // Pair registration and cleanup as one group; never suppress cleanup alone.
        Node network=one(index.methods.values(),n->args(n,CTX)
                &&n.text("android.net.conn.CONNECTIVITY_CHANGE")&&n.calls(CTX,"registerReceiver")
                &&create.calls.contains(n.id),"network registration");
        Clazz net=index.classes.get(network.id.owner);
        Node unregister=one(net.nodes,n->args(n,CTX)&&n.calls(CTX,"unregisterReceiver")
                &&cleanup.calls.contains(n.id),"network cleanup");
        add(g,network);add(g,unregister);
        Set<Id> distinct=new HashSet<>();
        for(Target t:g.targets)distinct.add(t.method);
        if(distinct.size()!=10)
            throw new IllegalArgumentException("listener target overlap");
    }
    static void api(DexIndex index,Group g,String kind,int position) {
        Node n=one(index.methods.values(),m->m.text("xsof_fraud_detection_"+kind)
                &&m.text("Call API 004_"+(position+1)+" from package : ")
                &&m.numbers.contains(1017L)&&m.calls("Landroid/os/Binder;","getCallingPid")
                &&m.isVoid(position==1?4:position==2?5:3),"api "+kind);
        List<String> args=n.id.args;
        if(!STR.equals(args.get(0))||!STR.equals(args.get(1)))throw new IllegalArgumentException("api argument shape");
        for(int i=2;i<args.size()-1;i++)if(!"[I".equals(args.get(i)))throw new IllegalArgumentException("api array shape");
        String callback=args.get(args.size()-1);
        List<Id> replies=new ArrayList<>();
        for(Id call:n.calls)if(call.owner.equals(n.id.owner)&&"V".equals(call.result)
                &&call.args.equals(Arrays.asList(callback,STR,"I"))) {
            Node helper=index.methods.get(call);
            if(helper==null)continue;
            for(Id reply:helper.calls)if(reply.owner.equals(callback)&&"V".equals(reply.result)
                    &&reply.args.equals(Arrays.asList(STR,"I"))&&!replies.contains(reply))replies.add(reply);
        }
        if(replies.size()!=1)throw new IllegalArgumentException("callback candidates="+replies.size());
        g.targets.add(new Target(n.id,replies.get(0)));
    }
    static Id id(String owner,String name,String... args) { return new Id("L"+owner.replace('.','/')+";",name,"V",args); }
    public static List<Group> known() {
        List<Group> out=new ArrayList<>();
        String service="com.xiaomi.security.xsof.frauddetection.service.MiFraudDetectionService";
        Group l=new Group("listeners");out.add(l);
        for(String n:new String[]{"r","s","o","p","q","t","x"})l.targets.add(new Target(id(service,n)));
        l.targets.add(new Target(id(service,"g",CTX)));
        for(String n:new String[]{"c","d"})l.targets.add(new Target(id("Ta.e",n,CTX)));
        String[][] rows={{"airplane_mode","V0","a"},{"install_app","X0","b"},
            {"call_forwarding","Z0","d"},{"screen_share","c1","j","Z1"},
            {"screenshot","e1","k"},{"fraud_phone","g1","m","b2"},
            {"fraud_url","i1","f"},{"voip_record","k1","n","d2"}};
        for(String[] row:rows) {
            Group g=new Group("storage."+row[0]);out.add(g);
            g.targets.add(new Target(id("Ra.k",row[1],"LQa/"+row[2]+";")));
            if(row.length>3)g.targets.add(new Target(row[0].equals("fraud_phone")?id("Ra.k",row[3],STR)
                    :row[0].equals("voip_record")?id("Ra.k",row[3],"LQa/n;","I"):id("Ra.k",row[3],"LQa/j;")));
        }
        Group p=new Group("provider.ingress");out.add(p);
        for(String n:new String[]{"a","b","c"})p.targets.add(new Target(id("com.xiaomi.security.xsof.frauddetection.provider.FraudDetectionProvider",n,VALUES)));
        String impl="com.xiaomi.security.xsof.MiSafetyDetectService$MiSafetyDetectImpl";
        String cb="Lcom/xiaomi/security/xsof/IMiSafetyDetectCallback;";
        String[][] api={{"current","c2"},{"past","f6"},{"duration","Q6"},{"score","b6"}};
        for(int i=0;i<api.length;i++) {
            List<String> a=new ArrayList<>(Arrays.asList(STR,STR));
            if(i==1||i==2)a.add("[I");if(i==2)a.add("[I");a.add(cb);
            Group g=new Group("api."+api[i][0]);out.add(g);
            g.targets.add(new Target(new Id("L"+impl.replace('.','/')+";",api[i][1],"V",a),new Id(cb,"G2","V",STR,"I")));
        }
        return out;
    }
}
