package com.h3xstream.findsecbugs.injection.convert;

import com.h3xstream.findsecbugs.injection.BasicInjectionDetector;
import com.h3xstream.findsecbugs.taintanalysis.TaintDataflow;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Location;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.Iterator;

public class Session_FixationDetector extends BasicInjectionDetector {
    private boolean creatSession = false;
    private boolean changeSession = false;
    SourceLineAnnotation sourceLine;
    public Session_FixationDetector(BugReporter bugReporter) {
        super(bugReporter);
    }

    @Override
    public void report(){
        if(creatSession == true && changeSession == false){
            bugReporter.reportBug(new BugInstance(this,"SESSION_FIXATION", Priorities.NORMAL_PRIORITY).addSourceLine(sourceLine));
        }
    }

    @Override
    protected void analyzeMethod(ClassContext classContext, Method method){
        try {
            TaintDataflow dataflow = getTaintDataFlow(classContext, method);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            //method
            String currentMethod = getFullMethodName(classContext.getMethodGen(method));

            for (Iterator<Location> i = getLocationIterator(classContext, method); i.hasNext(); ) {
                Location location = i.next();
                InstructionHandle handle = location.getHandle();
                TaintFrame fact = dataflow.getFactAtLocation(location);
                Instruction instruction = handle.getInstruction();
                if (!(instruction instanceof InvokeInstruction)) {
                    continue;
                }
                InvokeInstruction invoke = (InvokeInstruction) instruction;
                if(invoke.getMethodName(cpg).toLowerCase().contains("getsession")){
                    sourceLine = SourceLineAnnotation.fromVisitedInstruction(classContext, method, handle);
                    creatSession = true;
                }
                if(invoke.getMethodName(cpg).toLowerCase().contains("changeidsession")) changeSession = true;
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static Iterator<Location> getLocationIterator(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        try {
            return classContext.getCFG(method).locationIterator();
        } catch (CFGBuilderException ex) {
            throw new CheckedAnalysisException("cannot get control flow graph", ex);
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
}
