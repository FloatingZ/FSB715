package com.h3xstream.findsecbugs.TransferParamFieldReturn;

import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintDataflow;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSource;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSourceType;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Location;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.*;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.*;

public class ScanInfo {

    private static ScanInfo cf = new ScanInfo();
    public static int scanSwitch = 0;

    //return type
    public static Map<String,Set<String>> returnType = new HashMap<String,Set<String>>();
    public static Map<String, Map<Integer, Set<String>>> paToFd = new HashMap<String,Map<Integer, Set<String>>>();
    public static Map<String,Set<String>> fdToRt = new HashMap<>();
    public static Map<String,Set<Integer>> paToRt = new HashMap<>();
    public static Map<String,Map<Integer,Set<String>>> fdToPa = new HashMap<>();
    public static List<String> classList = new ArrayList<String>();
    //已扫描类
    public static Set<String> classSet = new HashSet<String>();
//    public static Map<String,Map<String,Set<Integer>>> paramToStaticField = new HashMap<String,Map<String, Set<Integer>>>();

    public static ScanInfo getInstance(){
        return  cf;
    }

    public void initClass(Collection<ClassDescriptor> classDescriptor){
        for(ClassDescriptor cd:classDescriptor){
            classList.add(cd.getClassName());
        }
    }

    public void visit(ClassDescriptor classDescriptor) throws CheckedAnalysisException{
        if(classSet.contains(classDescriptor.toString())) return;
        IAnalysisCache analysisCache = Global.getAnalysisCache();
        ClassContext classContext = analysisCache.getClassAnalysis(ClassContext.class, classDescriptor);
        this.visitClass(classContext);
    }

    public void visitClass(ClassContext classContext) throws CheckedAnalysisException{
        classSet.add(classContext.toString());
        for(Method method:classContext.getMethodsInCallOrder()){
            TaintDataflow dataflow = getTaintDataFlow(classContext, method);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            //method
            String currentMethod = getFullMethodName(classContext.getMethodGen(method));

            Set<String> typeset = new HashSet<String>();

            //for each method
            Map<Integer, Set<String>> mmap = new HashMap<Integer,Set<String>>();
            Set<Integer> msetp = new HashSet<Integer>();
            Set<String> msetf = new HashSet<String>();
            Map<Integer, Set<String>> mmaf = new HashMap<Integer,Set<String>>();
            Map<String,Set<Integer>> mss = new HashMap<String,Set<Integer>>();
            for (Iterator<Location> i = getLocationIterator(classContext, method); i.hasNext();) {
                Location location = i.next();
                InstructionHandle handle = location.getHandle();
                TaintFrame fact = dataflow.getFactAtLocation(location);
                Instruction instruction = handle.getInstruction();


                if(instruction instanceof PUTFIELD || instruction instanceof PUTSTATIC){
                    FieldInstruction inv = (FieldInstruction)instruction;
                    processPutfield(fact.getStackValue(0),inv,cpg,mmap);
                }


                if(instruction instanceof  ReturnInstruction){
                    if(instruction instanceof RETURN)   continue;
                    Taint t = fact.getStackValue(0);

                    int count = method.getArgumentTypes().length;
//                    Set<Integer> idxcount = t.getParameters();
                    List<Taint> sl = fact.getSlotList();
                    for (int idx = 0;idx<count;idx++) {
                        Taint pa = sl.get(idx);
                        for(UnknownSource us:pa.getSources()){
                            if(us.getSourceType()==UnknownSourceType.FIELD){
                                if (!mmaf.containsKey(idx)){
                                    Set<String> tmps = new HashSet<String>();
                                    tmps.add(us.getSignatureField());
                                    mmaf.put(idx,tmps);
                                }else{
                                    mmaf.get(idx).add(us.getSignatureField());
                                }
                            }
                        }
                    }
                    for(UnknownSource u:t.getSources()){
                        if(u.getSourceType()==UnknownSourceType.FIELD){
                            msetf.add(u.getSignatureField());
                        }
                        if(fact.getTopValue().getState() == Taint.State.SAFE) continue;
                        if(u.getSourceType() == UnknownSourceType.PARAMETER){
                                msetp.add(u.getParameterIndex());
                        }
                    }
                    if(t.getRealInstanceClass().getClassName() == null) continue;
                    String cn = t.getRealInstanceClass().getClassName();
                    if( cn != ""){
                        typeset.add(cn);
                    }
                }
            }
            if(typeset.size()>0){
                returnType.put(currentMethod,typeset);
            }
            if(mmap.size()>0){
                paToFd.put(currentMethod,mmap);
            }
            if(msetp.size()>0){
                paToRt.put(currentMethod,msetp);
            }
            if(msetf.size()>0){
                fdToRt.put(currentMethod,msetf);
            }
            if(mmaf.size()>0){
                fdToPa.put(currentMethod,mmaf);
            }
        }
    }

    protected void processPutfield(Taint t, FieldInstruction in, ConstantPoolGen cpg,Map<Integer, Set<String>> mmap){
        //fieldname
        String fname = in.getClassName(cpg).replaceAll("\\.","/")+"."+in.getName(cpg);
        Set<UnknownSource> s = t.getSources();

        for(UnknownSource us: s){
            if(us.getSourceType()== UnknownSourceType.PARAMETER){
                int idx = us.getParameterIndex();
                if(mmap.containsKey(idx)){
                    mmap.get(idx).add(fname);
                } else{
                    Set<String> tmps = new HashSet<String>();
                    tmps.add(fname);
                    mmap.put(idx,tmps);
                }
            }
        }
    }

    private static TaintDataflow getTaintDataFlow(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        MethodDescriptor descriptor = BCELUtil.getMethodDescriptor(classContext.getJavaClass(), method);
        return Global.getAnalysisCache().getMethodAnalysis(TaintDataflow.class, descriptor);
    }
    private static String getFullMethodName(MethodGen methodGen) {
        String methodNameWithSignature = methodGen.getName() + methodGen.getSignature();
        String slashedClassName = methodGen.getClassName().replace('.', '/');
        return slashedClassName + "." + methodNameWithSignature;
    }
    private static Iterator<Location> getLocationIterator(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        try {
            return classContext.getCFG(method).locationIterator();
        } catch (CFGBuilderException ex) {
            throw new CheckedAnalysisException("cannot get control flow graph", ex);
        }
    }
}
