package io.github.yunyizea.xsofprivacy;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.util.*;
import java.util.zip.*;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Read-only, process-local DEX index. Never executes target methods. */
public final class DexIndex {
    public final Map<String, Clazz> classes = new LinkedHashMap<>();
    public final Map<Id, Node> methods = new LinkedHashMap<>();
    public int dexCount;

    public static final class Id {
        public final String owner, name, result;
        public final List<String> args;
        public Id(String owner, String name, String result, String... args) {
            this(owner, name, result, Arrays.asList(args));
        }
        public Id(String owner, String name, String result, List<String> args) {
            this.owner=owner; this.name=name; this.result=result;
            this.args=Collections.unmodifiableList(new ArrayList<>(args));
        }
        static Id of(MethodReference m) {
            List<String> args=new ArrayList<>();
            for(CharSequence a:m.getParameterTypes()) args.add(a.toString());
            return new Id(m.getDefiningClass(),m.getName(),m.getReturnType(),args);
        }
        @Override public String toString() { return owner+"->"+name+"("+String.join("",args)+")"+result; }
        @Override public boolean equals(Object o) {
            if(!(o instanceof Id))return false;
            Id b=(Id)o;
            return owner.equals(b.owner)&&name.equals(b.name)&&result.equals(b.result)&&args.equals(b.args);
        }
        @Override public int hashCode() { return Objects.hash(owner,name,result,args); }
    }
    public static final class Node {
        public final Id id;
        public final int flags;
        public final Set<String> strings=new HashSet<>();
        public final Set<Long> numbers=new HashSet<>();
        public final Set<Id> calls=new HashSet<>();
        public Node(Id id,int flags) { this.id=id;this.flags=flags; }
        public boolean text(String s) { return strings.contains(s); }
        public boolean calls(String owner,String name) {
            for(Id call:calls)if(call.owner.equals(owner)&&call.name.equals(name))return true;
            return false;
        }
        public boolean isVoid(int arity) {
            return "V".equals(id.result)&&id.args.size()==arity
                    &&!id.name.startsWith("<")&&(flags&0x508)==0;
        }
    }
    public static final class Clazz {
        public final String type, parent;
        public final List<Node> nodes=new ArrayList<>();
        public Clazz(String type,String parent) { this.type=type;this.parent=parent; }
        public boolean text(String s) {
            for(Node n:nodes)if(n.text(s))return true;
            return false;
        }
    }
    public void add(Clazz c) {
        if(classes.put(c.type,c)!=null)throw new IllegalArgumentException("Duplicate DEX class "+c.type);
        for(Node n:c.nodes)if(methods.put(n.id,n)!=null)throw new IllegalArgumentException("Duplicate method");
    }
    public static DexIndex scan(List<String> apks) throws IOException {
        DexIndex out=new DexIndex();
        long bytes=0;
        for(String apk:apks)try(ZipFile zip=new ZipFile(apk)) {
            Enumeration<? extends ZipEntry> entries=zip.entries();
            while(entries.hasMoreElements()) {
                ZipEntry e=entries.nextElement();
                if(!e.getName().matches("classes([2-9][0-9]*|1[0-9]+)?\\.dex"))continue;
                long size=e.getSize();
                if(size<0||size>96L*1024*1024||(bytes+=size)>256L*1024*1024)
                    throw new IOException("DEX size limit exceeded");
                try(BufferedInputStream in=new BufferedInputStream(zip.getInputStream(e))) {
                    DexBackedDexFile dex=DexBackedDexFile.fromInputStream(Opcodes.getDefault(),in);
                    out.dexCount++;
                    for(ClassDef def:dex.getClasses()) {
                        Clazz c=new Clazz(def.getType(),def.getSuperclass());
                        for(org.jf.dexlib2.iface.Method method:def.getMethods()) {
                            Node n=new Node(Id.of(method),method.getAccessFlags());
                            MethodImplementation body=method.getImplementation();
                            if(body!=null)for(Instruction i:body.getInstructions()) {
                                if(i instanceof ReferenceInstruction) {
                                    Reference ref=((ReferenceInstruction)i).getReference();
                                    if(ref instanceof StringReference)n.strings.add(((StringReference)ref).getString());
                                    if(ref instanceof MethodReference)n.calls.add(Id.of((MethodReference)ref));
                                }
                                if(i instanceof NarrowLiteralInstruction)
                                    n.numbers.add((long)((NarrowLiteralInstruction)i).getNarrowLiteral());
                            }
                            c.nodes.add(n);
                        }
                        // Keep only semantic anchors; don't retain DEX buffers in results.
                        if(c.text("fraud_detection_data.db")||c.text("miui.intent.TAKE_SCREENSHOT")
                                ||c.text("com.xiaomi.security.xsof.FraudDetectionProvider")
                                ||c.text("android.net.conn.CONNECTIVITY_CHANGE")
                                ||c.text("xsof_fraud_detection_current")
                                ||c.text("xsof_fraud_detection_past")
                                ||c.text("xsof_fraud_detection_duration")
                                ||c.text("xsof_fraud_detection_score")
                                ||c.text("PHONE_SCAM_SCENE")||c.text("VIDEO_SCAM_SCENE")
                                ||c.text("operator_service_improve_plan")
                                ||c.text("application/encrypted-json")
                                ||c.text("QueryAppInfoThread")
                                ||c.type.startsWith("Lcom/mobiletools/systemhelper/control/"))out.add(c);
                    }
                }
            }
        }
        if(out.dexCount==0)throw new IOException("No standard classes*.dex found");
        return out;
    }
}
