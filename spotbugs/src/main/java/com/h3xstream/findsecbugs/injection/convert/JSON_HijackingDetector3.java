package com.h3xstream.findsecbugs.injection.convert;

import com.h3xstream.findsecbugs.injection.BasicInjectionDetector;
import com.h3xstream.findsecbugs.injection.InjectionPoint;
import com.h3xstream.findsecbugs.injection.InjectionSink;
import com.h3xstream.findsecbugs.taintanalysis.TaintDataflow;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.Location;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class JSON_HijackingDetector3 extends BasicInjectionDetector {
    private final Map<String, InjectionPoint> injectionMap = new HashMap<String, InjectionPoint>();

    boolean useSafeFrame = false;
    String safePackage = "dwr.util";
    String[] sinkMeth = new String[]{"select","exec"};
    String[] SensitiveClass = new String[]{"jsonobject","jsonvalue","jsonarray","jsonparser"};
    protected JSON_HijackingDetector3(BugReporter bugReporter) {
        super(bugReporter);
    }

    @Override
    protected void analyzeMethod(ClassContext classContext, Method method)
            throws CheckedAnalysisException {
        TaintDataflow dataflow = getTaintDataFlow(classContext, method);
        ConstantPoolGen cpg = classContext.getConstantPoolGen();
        //method
        String currentMethod = getFullMethodName(classContext.getMethodGen(method));

        for (Iterator<Location> i = getLocationIterator(classContext, method); i.hasNext();) {
            Location location = i.next();
            InstructionHandle handle = location.getHandle();
            TaintFrame fact = dataflow.getFactAtLocation(location);
            Instruction instruction = handle.getInstruction();

            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            InvokeInstruction invoke = (InvokeInstruction) instruction;

            assert fact != null;
            if (!fact.isValid()) {
                continue;
            }
            analyzeLocationTwo(classContext, method, handle, cpg, invoke, fact, currentMethod);
        }

    }
    protected void analyzeLocationTwo(ClassContext classContext, Method method, InstructionHandle handle,
                                   ConstantPoolGen cpg, InvokeInstruction invoke, TaintFrame fact, String currentMethod)
            throws DataflowAnalysisException {
        SourceLineAnnotation sourceLine = SourceLineAnnotation.fromVisitedInstruction(classContext, method, handle);
        String className = invoke.getClassName(cpg);
        String methodName = invoke.getMethodName(cpg);
        //检查是否使用安全的包
        if(className.contains(safePackage)){
            useSafeFrame = true;
        }
        //result = jason.DataInfluencedBy(db)
        if(methodName.contains("select")||methodName.contains("exec")){
            InjectionSink injectionSink = null;
            Type[] argType = invoke.getArgumentTypes(cpg);
            String classType = invoke.getClassName(cpg);
            for(String db:SensitiveClass){
                if(classType.toLowerCase().contains(db)){
                    bugReporter.reportBug(new BugInstance(this, "JSON_HIJACKING", Priorities.HIGH_PRIORITY)
                            .addClass(classContext.toString()).addSourceLine(sourceLine));
                }

                for(int offset = 0 ; offset<argType.length ; offset++){
                    if(argType[offset].toString().toLowerCase().contains(db))
                        bugReporter.reportBug(new BugInstance(this, "JSON_HIJACKING", Priorities.HIGH_PRIORITY)
                                .addClass(classContext.toString()).addSourceLine(sourceLine));
                }
            }
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
