package local.xsofprivacy;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.os.Binder;
import android.os.IInterface;
import de.robv.android.xposed.*;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.io.*;
import java.lang.reflect.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import local.xsofprivacy.CompatibilityResolver.*;
import local.xsofprivacy.DexIndex.Id;

/** Version-independent semantic profiles, with an exact-APK fast path. */
public final class PrivacyHook implements IXposedHookLoadPackage {
    private static final String TARGET="com.miui.securitycenter";
    private static final String KNOWN_SHA256=
            "f4eda1b7b0f46521c93ddc75f7d833aec7bd48674c561e545f2b84a1edd6284c";
    private static final AtomicBoolean ATTEMPTED=new AtomicBoolean();

    @Override public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if(!TARGET.equals(lp.packageName))return;
        XposedHelpers.findAndHookMethod(Application.class,"attach",Context.class,new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam p) {
                Context context=(Context)p.args[0];
                if(TARGET.equals(context.getPackageName())&&ATTEMPTED.compareAndSet(false,true))
                    install(context,lp.classLoader,lp.processName);
            }
        });
    }

    private static void install(Context context,ClassLoader loader,String process) {
        long started=System.nanoTime();
        try {
            PackageInfo info=context.getPackageManager().getPackageInfo(TARGET,0);
            List<String> apks=new ArrayList<>();
            apks.add(context.getApplicationInfo().sourceDir);
            String[] splits=(String[])context.getApplicationInfo().getClass()
                    .getField("splitSourceDirs").get(context.getApplicationInfo());
            if(splits!=null)Collections.addAll(apks,splits);
            boolean exact=apks.size()==1&&KNOWN_SHA256.equals(hash(apks.get(0)));
            List<Group> groups;
            if(exact)groups=CompatibilityResolver.known();
            else {
                // Synchronous before provider/service setup; no stale disk cache.
                DexIndex index=DexIndex.scan(apks);
                groups=CompatibilityResolver.discover(index);
                log(process,"SCAN dex="+index.dexCount+" anchorClasses="+index.classes.size());
            }
            log(process,"PROFILE="+(exact?"EXACT_APK":"ADAPTIVE_UNVERIFIED")+" version="+info.versionName);
            int installed=0,skipped=0,hooks=0;
            Set<Id> used=new HashSet<>();
            for(Group group:groups) {
                if(group.skip!=null) {
                    skipped++;log(process,"SKIPPED "+group.name+" "+group.skip);continue;
                }
                int count=installGroup(group,loader,process,used);
                if(count>0){installed++;hooks+=count;}else skipped++;
            }
            log(process,"SUMMARY installedGroups="+installed+" skippedOrFailedGroups="+skipped
                    +" hooks="+hooks+" elapsedMs="+((System.nanoTime()-started)/1000000)
                    +"; registration only, verify HIT and device behavior");
        } catch(Throwable error) {
            log(process,"DISCOVERY_FAILED no additional groups installed: "+error.getClass().getSimpleName());
        }
    }

    private static int installGroup(Group group,ClassLoader loader,String process,Set<Id> used) {
        List<XC_MethodHook.Unhook> handles=new ArrayList<>();
        try {
            List<Method> methods=new ArrayList<>(),replies=new ArrayList<>();
            Set<Id> local=new HashSet<>();
            for(Target target:group.targets) {
                if(used.contains(target.method)||!local.add(target.method))
                    throw new IllegalArgumentException("overlapping target");
                Method method=resolve(target.method,loader);
                if(method.getReturnType()!=void.class||Modifier.isStatic(method.getModifiers())
                        ||Modifier.isAbstract(method.getModifiers())||Modifier.isNative(method.getModifiers()))
                    throw new IllegalArgumentException("unsupported target signature");
                Method reply=null;
                if(target.callback!=null) {
                    reply=resolve(target.callback,loader);
                    if(!Binder.class.isAssignableFrom(method.getDeclaringClass())
                            ||!IInterface.class.isAssignableFrom(reply.getDeclaringClass())
                            ||!reply.getDeclaringClass().isInterface()||Modifier.isStatic(reply.getModifiers())
                            ||!method.getParameterTypes()[method.getParameterCount()-1].equals(reply.getDeclaringClass())
                            ||reply.getReturnType()!=void.class)
                        throw new IllegalArgumentException("unsupported Binder contract");
                }
                methods.add(method);replies.add(reply);
            }
            for(int i=0;i<methods.size();i++) {
                final Target target=group.targets.get(i);
                final Method reply=replies.get(i);
                AtomicBoolean first=new AtomicBoolean(true),replyFailed=new AtomicBoolean();
                handles.add(XposedBridge.hookMethod(methods.get(i),new XC_MethodHook(10000) {
                    @Override protected void beforeHookedMethod(MethodHookParam p) {
                        if(first.compareAndSet(true,false))log(process,"HIT "+group.name+" "+target.method);
                        p.setResult(null);
                        if(reply!=null) {
                            Object callback=p.args[p.args.length-1];
                            if(callback!=null)try {
                                // Recognized profiles use the ACCESS_XSOF rejection code.
                                reply.invoke(callback,new Object[]{null,1017});
                            } catch(Throwable failure) {
                                if(replyFailed.compareAndSet(false,true))
                                    log(process,"CALLBACK_FAILED "+group.name+" "+failure.getClass().getSimpleName());
                            }
                        }
                    }
                }));
            }
            used.addAll(local);
            log(process,"INSTALLED "+group.name+" hooks="+handles.size());
            return handles.size();
        } catch(Throwable failure) {
            boolean undone=true;
            for(XC_MethodHook.Unhook hook:handles)try{hook.unhook();}catch(Throwable ignored){undone=false;}
            log(process,(undone?"FAILED ":"FAILED_ROLLBACK_INCOMPLETE ")+group.name+" "+failure.getClass().getSimpleName());
            return 0;
        }
    }
    private static Method resolve(Id id,ClassLoader loader) throws Exception {
        Class<?>[] args=new Class<?>[id.args.size()];
        for(int i=0;i<args.length;i++)args[i]=type(id.args.get(i),loader);
        Method method=type(id.owner,loader).getDeclaredMethod(id.name,args);
        if(method.getReturnType()!=type(id.result,loader))throw new NoSuchMethodException(id.toString());
        method.setAccessible(true);
        return method;
    }
    private static Class<?> type(String descriptor,ClassLoader loader) throws ClassNotFoundException {
        switch(descriptor) {
            case "V":return void.class;case "I":return int.class;case "Z":return boolean.class;
            case "J":return long.class;case "B":return byte.class;case "S":return short.class;
            case "C":return char.class;case "F":return float.class;case "D":return double.class;
            default:
                String name=descriptor.startsWith("L")?descriptor.substring(1,descriptor.length()-1):descriptor;
                return Class.forName(name.replace('/','.'),false,loader);
        }
    }
    private static String hash(String path) throws Exception {
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        try(InputStream input=new FileInputStream(path)) {
            byte[] buffer=new byte[65536];int n;
            while((n=input.read(buffer))!=-1)md.update(buffer,0,n);
        }
        StringBuilder out=new StringBuilder(64);
        for(byte b:md.digest())out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static void log(String process,String text) { XposedBridge.log("[XsofPrivacy]["+process+"] "+text); }
}
