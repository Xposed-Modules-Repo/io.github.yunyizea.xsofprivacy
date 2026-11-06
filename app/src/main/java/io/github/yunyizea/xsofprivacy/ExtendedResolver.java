package io.github.yunyizea.xsofprivacy;

import java.util.*;
import io.github.yunyizea.xsofprivacy.DexIndex.*;
import io.github.yunyizea.xsofprivacy.CompatibilityResolver.*;
import static io.github.yunyizea.xsofprivacy.CompatibilityResolver.*;

/** Separate optional scopes. No global URL/recording/location hooks. */
public final class ExtendedResolver {
    public static final String GUARD="com.miui.guardprovider";
    public static final String HELPER="com.mobiletools.systemhelper";
    public static String reviewedSha(String pkg) {
        if(GUARD.equals(pkg))return "eff2c614d054263068e931f859f2e9fb4c66e31f960d815ab507abbdff15bb5d";
        if(HELPER.equals(pkg))return "1de8d965e295db27e189aa179cdb45438d7f759cffbb43ce55f840b614ff6c65";
        return null;
    }
    public static List<Group> known(String pkg) {
        List<Group> out=new ArrayList<>();
        if(GUARD.equals(pkg)) {
            Group g=new Group("guard.ai_detection");out.add(g);
            g.targets.add(new Target(new Id("Lcom/miui/guardprovider/aiguard/AiGuardService;",
                    "onStartCommand","I","Landroid/content/Intent;","I","I"),null,Target.STOP_SERVICE));
        }
        if(HELPER.equals(pkg)) {
            Group gate=new Group("helper.policy_gate");out.add(gate);
            gate.targets.add(new Target(new Id("Lg1/l;","a","Z",CTX),null,Target.FALSE));
            Group post=new Group("helper.encrypted_post");out.add(post);
            post.targets.add(new Target(new Id("Lg1/f;","b","Z",STR,"[B","[B"),null,Target.FALSE));
            Group usage=new Group("helper.app_usage");out.add(usage);
            usage.targets.add(new Target(new Id("Le1/f;","run","V")));
            for(String name:new String[]{"AppInfoRegisterReceiver","ScheduleRegisterReceiver",
                    "GetSignalInfoReceiver","SignalInfoRegisterReceiver","OnBootReceiver",
                    "SIMStateReceiver","ConnectStateReceiver"}) {
                Group g=new Group("helper.receiver."+name);out.add(g);
                g.targets.add(new Target(new Id("Lcom/mobiletools/systemhelper/control/"+name+";",
                        "onReceive","V",CTX,"Landroid/content/Intent;")));
            }
        }
        return out;
    }
    public static List<Group> discover(String pkg,DexIndex index) {
        List<Group> groups=new ArrayList<>();
        if(GUARD.equals(pkg))group(groups,"guard.ai_detection",g->{
            Clazz service=clazz(index,c->"Landroid/app/Service;".equals(c.parent)
                    &&c.text("PHONE_SCAM_SCENE")&&c.text("VIDEO_SCAM_SCENE")
                    &&c.text("ai_guard_function_switch"),"AI detection service");
            Node start=one(service.nodes,n->n.id.name.equals("onStartCommand")
                    &&n.id.result.equals("I")&&n.id.args.equals(Arrays.asList("Landroid/content/Intent;","I","I"))
                    &&n.text("COMMAND")&&n.text("CAPABILITIES")
                    &&n.text("PHONE_SCAM_SCENE")&&n.text("VIDEO_SCAM_SCENE")
                    &&n.calls("Landroid/app/Service;","startForeground")
                    &&(n.flags&0x508)==0,"AI command entry");
            g.targets.add(new Target(start.id,null,Target.STOP_SERVICE));
        });
        if(HELPER.equals(pkg)) {
            group(groups,"helper.policy_gate",g->{
                Node gate=one(index.methods.values(),n->n.id.result.equals("Z")
                        &&n.id.args.equals(Collections.singletonList(CTX))&&(n.flags&8)!=0
                        &&n.text("operator_service_improve_plan")&&n.text("device_provisioned")
                        &&n.text("RegisterUtils")&&n.text("checkUserPermission:")
                        &&n.calls("Landroid/provider/Settings$Secure;","getInt")
                        &&n.calls("Landroid/provider/Settings$Global;","getInt"),"helper consent gate");
                g.targets.add(new Target(gate.id,null,Target.FALSE));
            });
            group(groups,"helper.encrypted_post",g->{
                // Legacy implementations have one sender. Newer implementations
                // need both the encrypted sender and its caller-linked fallback.
                Clazz sender=clazz(index,c->c.text("HttpHelper")
                        &&c.text("sendHttpRequest() path = ")
                        &&c.text("application/encrypted-json"),"helper telemetry class");
                List<Node> senders=new ArrayList<>();
                for(Node n:sender.nodes)if(telemetrySender(n))senders.add(n);
                Node encrypted=one(senders,n->n.id.args.equals(Arrays.asList(STR,"[B","[B"))
                        &&n.text("application/encrypted-json"),"helper encrypted sender");
                if(senders.size()==1) {
                    // Never mistake a partially recognized newer implementation
                    // for the reviewed legacy single-sender shape.
                    if(!encrypted.text("register success!")||sender.text("HTTPS register success!"))
                        throw new IllegalArgumentException("unverified single telemetry sender");
                    g.targets.add(new Target(encrypted.id,null,Target.FALSE));
                } else {
                    if(senders.size()!=2)throw new IllegalArgumentException(
                            "helper telemetry senders="+senders.size());
                    Node fallback=one(senders,n->n.id.args.equals(Arrays.asList(STR,"[B")),
                            "helper fallback sender");
                    boolean linked=false;
                    for(Node caller:index.methods.values())
                        if(caller.calls.contains(encrypted.id)&&caller.calls.contains(fallback.id))linked=true;
                    if(!linked)throw new IllegalArgumentException("unlinked telemetry fallback");
                    g.targets.add(new Target(encrypted.id,null,Target.FALSE));
                    g.targets.add(new Target(fallback.id,null,Target.FALSE));
                }
            });
            group(groups,"helper.app_usage",g->{
                Clazz worker=clazz(index,c->"Ljava/lang/Thread;".equals(c.parent)
                        &&c.text("QueryAppInfoThread")
                        &&c.text("queryAppUsageStatsDescend  isUserPermissionOpen :"),"usage thread");
                Node collect=one(worker.nodes,n->n.calls("Landroid/content/pm/PackageManager;","getInstalledApplications")
                        &&n.text("usagestats"),"usage enumeration");
                Node run=one(worker.nodes,n->args(n)&&n.id.name.equals("run")
                        &&n.calls.contains(collect.id),"usage thread run");
                add(g,run);
            });
            for(String name:new String[]{"AppInfoRegisterReceiver","ScheduleRegisterReceiver",
                    "GetSignalInfoReceiver","SignalInfoRegisterReceiver","OnBootReceiver",
                    "SIMStateReceiver","ConnectStateReceiver"}) {
                group(groups,"helper.receiver."+name,g->{
                    Clazz receiver=clazz(index,c->c.type.equals("Lcom/mobiletools/systemhelper/control/"+name+";")
                            &&"Landroid/content/BroadcastReceiver;".equals(c.parent),"helper receiver");
                    add(g,one(receiver.nodes,n->n.id.name.equals("onReceive")
                            &&args(n,CTX,"Landroid/content/Intent;"),"receiver entry"));
                });
            }
        }
        return groups;
    }

    private static boolean telemetrySender(Node n) {
        return "Z".equals(n.id.result)&&(n.flags&0x508)==0
                &&n.id.args.contains(STR)&&n.id.args.contains("[B")
                &&n.calls("Ljava/net/URL;","openConnection")
                &&n.calls("Ljava/net/URLConnection;","getOutputStream")
                &&n.calls("Ljava/net/HttpURLConnection;","getResponseCode");
    }
}
