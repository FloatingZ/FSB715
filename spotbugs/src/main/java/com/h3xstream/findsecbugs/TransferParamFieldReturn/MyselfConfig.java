package com.h3xstream.findsecbugs.TransferParamFieldReturn;

import com.h3xstream.findsecbugs.taintanalysis.*;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSource;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSourceType;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Location;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.*;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

public class MyselfConfig {
    private static MyselfConfig myselfConfig = new MyselfConfig();
    private TaintConfig taintConfig;

    private MyselfConfig(){}

    public static MyselfConfig getMyselfConfig(){
        return myselfConfig;
    }

    public void setTaintConfig(TaintConfig taintConfig) {
        this.taintConfig = taintConfig;
    }

    public void visit(ClassDescriptor classDescriptor) throws CheckedAnalysisException{
        if(taintConfig == null) return;
        if(taintConfig.getTaintClassConfig("L"+classDescriptor.toString().replace('.','/')+';')!=null) {
            return;
        }
        IAnalysisCache analysisCache = Global.getAnalysisCache();
        ClassContext classContext = analysisCache.getClassAnalysis(ClassContext.class, classDescriptor);
        this.visitClass(classContext);
    }

    public void visitClass(ClassContext classContext) throws CheckedAnalysisException {
        for (Method method : classContext.getMethodsInCallOrder()) {
            StringBuffer key = new StringBuffer(classContext.toString().replace('.','/'));
            key.append('.');
            key.append(method.getName());
            key.append(method.getSignature());
            String typeSignature = key.toString();
            if(taintConfig.containsKey(key.toString())) return;
            TaintDataflow dataflow = getTaintDataFlow(classContext, method);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            ArrayList<Integer> param = new ArrayList<Integer>();
            boolean influcebyself = false;
            boolean mutable = false;
            boolean tag = true;
            int dep = 0;
            int N = 0;
            Type[] arguementTypes = method.getArgumentTypes();
            for(Type type:arguementTypes){
                N += type.getSize();
            }

//            for(String str:taintConfig.keySet()){
//                if(str.startsWith("L")) {
//                    String ss = str;
//                }
//            }

            //method
            String currentMethod = getFullMethodName(classContext.getMethodGen(method));
            for (Iterator<Location> i = getLocationIterator(classContext, method); i.hasNext();) {
                Location location = i.next();
                InstructionHandle handle = location.getHandle();
                TaintFrame fact = dataflow.getFactAtLocation(location);
                Instruction instruction = handle.getInstruction();


                if( instruction instanceof PUTFIELD||instruction instanceof  PUTSTATIC){
                    if(fact.getStackDepth() == 0) return;
                    FieldInstruction inv = (FieldInstruction)instruction;
                    Taint t = fact.getTopValue();
                    Set<UnknownSource> s = t.getSources();
                    for(UnknownSource us:s){
                        if(us.getSourceType() == UnknownSourceType.PARAMETER){
                            mutable = true;
                        }
                    }
                } else if(instruction instanceof ReturnInstruction){
                    if(fact.getStackDepth() == 0) return;
                    Taint t = fact.getTopValue();
                    Set<UnknownSource> s = t.getSources();
                    for(UnknownSource us:s){
                        if(us.getSourceType() == UnknownSourceType.FIELD) influcebyself = true;
                        if(us.getSourceType() == UnknownSourceType.PARAMETER) param.add(us.getParameterIndex());
                    }
                } else{

                }
            }

            String config ="";
            if(param.size() == 0 && influcebyself == false) config = "SAFE";
            else {
                for(int index:param){
                    config += index+',';
                }
                if(influcebyself) config += N;
                else    config = config.substring(0,config.length());
            }
            if(mutable) config += "#"+(N);


            try{
                if(!TaintMethodConfig.accepts(typeSignature,config)) return;

                TaintMethodConfig taintMethodConfig = new TaintMethodConfig(true).load(config);
                taintMethodConfig.setTypeSignature(typeSignature);
                taintConfig.put(typeSignature, taintMethodConfig);
            }catch (Exception e){
                e.printStackTrace();
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
