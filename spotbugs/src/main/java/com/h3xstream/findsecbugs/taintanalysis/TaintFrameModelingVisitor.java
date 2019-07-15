/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.taintanalysis;

import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import com.h3xstream.findsecbugs.TransferParamFieldReturn.PropritiesHelper;
import com.h3xstream.findsecbugs.TransferParamFieldReturn.ScanInfo;
import com.h3xstream.findsecbugs.common.ByteCode;
import com.h3xstream.findsecbugs.taintanalysis.data.TaintLocation;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSource;
import com.h3xstream.findsecbugs.taintanalysis.data.UnknownSourceType;
import edu.umd.cs.findbugs.ba.AbstractFrameModelingVisitor;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import edu.umd.cs.findbugs.ba.InvalidBytecodeException;
import edu.umd.cs.findbugs.ba.ca.Call;
import edu.umd.cs.findbugs.ba.generic.GenericSignatureParser;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.util.ClassName;
import org.apache.bcel.Const;
import org.apache.bcel.generic.*;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Visitor to make instruction transfer of taint values easier
 *
 * @author David Formanek (Y Soft Corporation, a.s.)
 */
public class TaintFrameModelingVisitor extends AbstractFrameModelingVisitor<Taint, TaintFrame> {

    private static final Logger LOG = Logger.getLogger(TaintFrameModelingVisitor.class.getName());

    private static final Map<String, Taint.Tag> REPLACE_TAGS;
    private final MethodDescriptor methodDescriptor;
    private final TaintConfig taintConfig;
    private final TaintMethodConfig analyzedMethodConfig;
    private final List<TaintFrameAdditionalVisitor> visitors;
    private final MethodGen methodGen;

    static {
        REPLACE_TAGS = new HashMap<String, Taint.Tag>();
        REPLACE_TAGS.put("\r", Taint.Tag.CR_ENCODED);
        REPLACE_TAGS.put("\n", Taint.Tag.LF_ENCODED);
        REPLACE_TAGS.put("\"", Taint.Tag.QUOTE_ENCODED);
        REPLACE_TAGS.put("'", Taint.Tag.APOSTROPHE_ENCODED);
        REPLACE_TAGS.put("<", Taint.Tag.LT_ENCODED);
    }

    /**
     * Constructs the object and stores the parameters
     *
     * @param cpg constant pool gen for super class
     * @param method descriptor of analysed method
     * @param taintConfig current configured and derived taint summaries
     * @throws NullPointerException if arguments method or taintConfig is null
     */
    public TaintFrameModelingVisitor(ConstantPoolGen cpg, MethodDescriptor method,
                                     TaintConfig taintConfig, List<TaintFrameAdditionalVisitor> visitors, MethodGen methodGen) {
        super(cpg);
        if (method == null) {
            throw new NullPointerException("null method descriptor");
        }
        if (taintConfig == null) {
            throw new NullPointerException("null taint config");
        }
        this.methodDescriptor = method;
        this.taintConfig = taintConfig;
        this.analyzedMethodConfig = new TaintMethodConfig(false);
        this.visitors = visitors;
        this.methodGen = methodGen;
    }

    @Override
    public void setParament() {
        super.setParament();
        Type[] tp = methodGen.getArgumentTypes();
        int argueNum = tp.length;
        if(argueNum>0 &&getFrame().getSlotList().size()>0 &&getFrame().getValue(0).getRealInstanceClass()==null){
            for(int i = 0 ; i < argueNum ; i++){
                String s = tp[i].toString();
                getFrame().getValue(i).setRealInstanceClass(new ObjectType(s));
            }
        }
    }

    private Collection<Integer> getMutableStackIndices(String signature) {
        assert signature != null && !signature.isEmpty();
        ArrayList<Integer> indices = new ArrayList<Integer>();
        int stackIndex = 0;
        GenericSignatureParser parser = new GenericSignatureParser(signature);
        Iterator<String> iterator = parser.parameterSignatureIterator();
        while (iterator.hasNext()) {
            String parameter = iterator.next();
            if ((parameter.startsWith("L") || parameter.startsWith("["))
                    && !taintConfig.isClassImmutable(parameter)) {
                indices.add(stackIndex);
            }
            if (parameter.equals("D") || parameter.equals("J")) {
                // double and long types takes two slots
                stackIndex += 2;
            } else {
                stackIndex++;
            }
        }
        for (int i = 0; i < indices.size(); i++) {
            int reverseIndex = stackIndex - indices.get(i) - 1;
            assert reverseIndex >= 0;
            indices.set(i, reverseIndex);
        }
        return indices;
    }

    @Override
    public void analyzeInstruction(Instruction ins) throws DataflowAnalysisException {
        //Print the bytecode instruction if it is globally configured
        if (FindSecBugsGlobalConfig.getInstance().isDebugPrintInvocationVisited()
                && ins instanceof InvokeInstruction) {
            //System.out.println(getFrame().toString());
            ByteCode.printOpCode(ins, cpg);
        } else if (FindSecBugsGlobalConfig.getInstance().isDebugPrintInstructionVisited()) {
            ByteCode.printOpCode(ins, cpg);
        }
        super.analyzeInstruction(ins);
    }

    @Override
    public Taint getDefaultValue() {
        return new Taint(Taint.State.UNKNOWN);
    }

    @Override
    public void visitLDC(LDC ldc) {
        Taint taint = new Taint(Taint.State.SAFE);
        Object value = ldc.getValue(cpg);
        if (value instanceof String) {
            taint.setConstantValue((String) value);
        }
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            if (value instanceof String) {
                taint.setDebugInfo("\"" + value + "\"");
            } else {
                taint.setDebugInfo("LDC " + ldc.getType(cpg).getSignature());
            }
        }
        getFrame().pushValue(taint);
    }

    @Override
    public void visitLDC2_W(LDC2_W obj) {
        // double and long type takes two slots in BCEL
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            pushSafeDebug("partial long/double");
            pushSafeDebug("partial long/double");
        } else {
            pushSafe();
            pushSafe();
        }
    }

    @Override
    public void visitBIPUSH(BIPUSH obj) {
        Taint taint = new Taint(Taint.State.SAFE);
        // assume each pushed byte is a char
        taint.setConstantValue(String.valueOf(obj.getValue()));
        getFrame().pushValue(taint);
    }

    @Override
    public void visitSIPUSH(SIPUSH obj) {
        Taint taint = new Taint(Taint.State.SAFE);
        // assume each pushed short is a char (for non-ASCII characters)
        taint.setConstantValue(String.valueOf((char) obj.getValue().shortValue()));
        getFrame().pushValue(taint);
    }

    @Override
    public void visitGETSTATIC(GETSTATIC obj) {
        // Scala uses some classes to represent null instances of objects
        // If we find one of them, we will handle it as a Java Null
        if (obj.getLoadClassType(getCPG()).getSignature().equals("Lscala/collection/immutable/Nil$;")) {

            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
                getFrame().pushValue(new Taint(Taint.State.NULL).setDebugInfo("NULL"));
            } else {
                getFrame().pushValue(new Taint(Taint.State.NULL));
            }
        } else {
            //super.visitGETSTATIC(obj);
            String fieldSig = obj.getClassName(cpg).replaceAll("\\.","/")+"."+obj.getName(cpg);
            Taint.State state = taintConfig.getClassTaintState(fieldSig, Taint.State.UNKNOWN);
            Taint taint = new Taint(state);

            if (!state.equals(Taint.State.SAFE)){
                taint.addLocation(getTaintLocation(), false);
            }
            taint.addSource(new UnknownSource(UnknownSourceType.FIELD,state).setSignatureField(fieldSig));

            int numConsumed = getNumWordsConsumed(obj);
            int numProduced = getNumWordsProduced(obj);
            modelInstruction(obj, numConsumed, numProduced, taint);

            notifyAdditionalVisitorField(obj, methodGen, getFrame(), taint, numProduced);
        }
    }

    @Override
    public void visitACONST_NULL(ACONST_NULL obj) {
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            getFrame().pushValue(new Taint(Taint.State.NULL).setDebugInfo("NULL"));
        } else {
            getFrame().pushValue(new Taint(Taint.State.NULL));
        }
    }

    @Override
    public void visitICONST(ICONST obj) {
        Taint t = new Taint(Taint.State.SAFE);
        t.setConstantValue(String.valueOf(obj.getValue()));
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            t.setDebugInfo("" + obj.getValue().intValue());
        }
        getFrame().pushValue(t);
    }

    @Override
    public void visitGETFIELD(GETFIELD obj) {
        String fieldSig = obj.getClassName(cpg).replaceAll("\\.","/")+"."+obj.getName(cpg);
        Taint.State state = taintConfig.getClassTaintState(fieldSig, Taint.State.UNKNOWN);
        Taint taint = new Taint(state);

        if (!state.equals(Taint.State.SAFE)){
            taint.addLocation(getTaintLocation(), false);
        }
        taint.addSource(new UnknownSource(UnknownSourceType.FIELD,state).setSignatureField(fieldSig));
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            taint.setDebugInfo("." + obj.getFieldName(cpg));
        }
        int numConsumed = getNumWordsConsumed(obj);
        int numProduced = getNumWordsProduced(obj);
        modelInstruction(obj, numConsumed, numProduced, taint);


        notifyAdditionalVisitorField(obj, methodGen, getFrame(), taint, numProduced);
    }

    @Override
    public void visitPUTFIELD(PUTFIELD obj) {
        visitPutFieldOp(obj);
    }

    @Override
    public void visitPUTSTATIC(PUTSTATIC obj) {
        visitPutFieldOp(obj);
    }

    public void visitPutFieldOp(FieldInstruction obj) {

        int numConsumed = getNumWordsConsumed(obj);
        int numProduced = getNumWordsProduced(obj);
        try {
            Taint t = getFrame().getTopValue();
            handleNormalInstruction(obj);
            notifyAdditionalVisitorField(obj, methodGen, getFrame(), t, numProduced);
        } catch (DataflowAnalysisException e) {

        }

    }

    private void notifyAdditionalVisitorField(FieldInstruction instruction, MethodGen methodGen, TaintFrame frame,
                                              Taint taintValue, int numProduced) {
        for(TaintFrameAdditionalVisitor visitor : visitors) {
            try {
                visitor.visitField(instruction, methodGen, frame, taintValue, numProduced, cpg);
            }
            catch (Throwable e) {
                LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
            }
        }
    }

    @Override
    public void visitNEW(NEW obj) {
        Taint taint = new Taint(Taint.State.SAFE);
        ObjectType type = obj.getLoadClassType(cpg);
        taint.setRealInstanceClass(type);
        if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
            taint.setDebugInfo("new " + type.getClassName() + "()");
        }
        getFrame().pushValue(taint);
    }

    @Override
    public void handleStoreInstruction(StoreInstruction obj) {
        try {
            int numConsumed = obj.consumeStack(cpg);
            if (numConsumed == Const.UNPREDICTABLE) {
                throw new InvalidBytecodeException("Unpredictable stack consumption");
            }
            int index = obj.getIndex();
            while (numConsumed-- > 0) {
                Taint value = new Taint(getFrame().popValue());
                value.setVariableIndex(index);
                getFrame().setValue(index++, value);
            }
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException(ex.toString(), ex);
        }
    }

    @Override
    public void handleLoadInstruction(LoadInstruction load) {
        int numProducedOrig = load.produceStack(cpg);
        int numProduced = numProducedOrig;
        if (numProduced == Const.UNPREDICTABLE) {
            throw new InvalidBytecodeException("Unpredictable stack production");
        }
        int index = load.getIndex() + numProduced;
        while (numProduced-- > 0) {
            Taint value = getFrame().getValue(--index);
            //assert value.hasValidVariableIndex() :
            if(!value.hasValidVariableIndex()) {
                throw new RuntimeException("index not set in " + methodDescriptor);
            }
            if(index != value.getVariableIndex()) {
                throw new RuntimeException("bad index in " + methodDescriptor);
            }
            getFrame().pushValue(new Taint(value));
        }

        for(TaintFrameAdditionalVisitor visitor : visitors) {
            try {
                visitor.visitLoad(load, methodGen, getFrame(), numProducedOrig, cpg);
            }
            catch (Throwable e) {
                LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
            }
        }
    }

    @Override
    public void visitINVOKEINTERFACE(INVOKEINTERFACE obj) {
        visitInvoke(obj);
    }

    @Override
    public void visitINVOKESPECIAL(INVOKESPECIAL obj) {
        visitInvoke(obj);
    }

    @Override
    public void visitINVOKESTATIC(INVOKESTATIC obj) {
        visitInvoke(obj);
    }

    @Override
    public void visitINVOKEVIRTUAL(INVOKEVIRTUAL obj) {
        visitInvoke(obj);
    }

//    @Override
//    public void visitANEWARRAY(ANEWARRAY obj) {
//        try {
//            getFrame().popValue();
//            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
//                pushSafeDebug("new " + obj.getLoadClassType(cpg).getClassName() + "[]");
//            } else {
//                pushSafe();
//            }
//        } catch (DataflowAnalysisException ex) {
//            throw new InvalidBytecodeException("Array length not in the stack", ex);
//        }
//    }
    @Override
    public void visitANEWARRAY(ANEWARRAY obj) {
        try {
            getFrame().popValue();
            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
                pushSafeDebug("new " + obj.getLoadClassType(cpg).getClassName() + "[]");
            } else {
                pushSafe();
            }
            Taint top = getFrame().getTopValue();
            top.initArray();
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("Array length not in the stack", ex);
        }
    }

//    @Override
//    public void visitAASTORE(AASTORE obj) {
//        try {
//            Taint valueTaint = getFrame().popValue();
//            getFrame().popValue(); // array index
//            Taint arrayTaint = getFrame().popValue();
//            Taint merge = Taint.merge(valueTaint, arrayTaint);
//            setLocalVariableTaint(merge, arrayTaint);
//            Taint stackTop = null;
//            if (getFrame().getStackDepth() > 0) {
//                stackTop = getFrame().getTopValue();
//            }
//            // varargs use duplicated values
//            if (stackTop == arrayTaint) {
//                getFrame().popValue();
//                getFrame().pushValue(new Taint(merge));
//            }
//        } catch (DataflowAnalysisException ex) {
//            throw new InvalidBytecodeException("Not enough values on the stack", ex);
//        }
//    }
    @Override
    public void visitAASTORE(AASTORE obj) {
        try {
            Taint.State valueState = getFrame().popValue().getState();
            Taint idxTaint = getFrame().popValue();
            int idxVal = Integer.parseInt(idxTaint.getConstantValue());
            Taint arrayTaint = getFrame().popValue();
            arrayTaint.innerArray.put(idxVal,valueState);
            setLocalVariableTaint(arrayTaint, arrayTaint);
            Taint stackTop = null;
            if (getFrame().getStackDepth() > 0) {
                stackTop = getFrame().getTopValue();
            }
            // varargs use duplicated values
            if (stackTop == arrayTaint) {
                getFrame().popValue();
                getFrame().pushValue(new Taint(arrayTaint));
            }
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("Not enough values on the stack", ex);
        }
    }
//    @Override
//    public void visitAALOAD(AALOAD obj) {
//        try {
//            getFrame().popValue(); // array index
//            // just transfer the taint from array to value at any index
//        } catch (DataflowAnalysisException ex) {
//            throw new InvalidBytecodeException("Not enough values on the stack", ex);
//        }
//    }
    @Override
    public void visitAALOAD(AALOAD obj) {
        try {
            Taint idx = getFrame().popValue(); // array index
            int idxValue = Integer.parseInt(idx.getConstantValue());
            Taint.State ls = getFrame().getTopValue().innerArray.get(idxValue);
            if(ls != null) getFrame().getTopValue().setState(ls);
            else getFrame().getTopValue().setState(Taint.State.SAFE);
            // just transfer the taint from array to value at any index
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("Not enough values on the stack", ex);
        }
    }


    @Override
    public void visitCHECKCAST(CHECKCAST obj) {
        // cast to a safe object type
        ObjectType objectType = obj.getLoadClassType(cpg);
        if (objectType == null) {
            return;
        }

        String objectTypeSignature = objectType.getSignature();

        if(!taintConfig.isClassTaintSafe(objectTypeSignature)) {
            return;
        }

        try {
            getFrame().popValue();
            pushSafe();
        }
        catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("empty stack for checkcast", ex);
        }
    }

    @Override
    public void visitARETURN(ARETURN obj) {
        Taint returnTaint = null;
        try {
            returnTaint = getFrame().getTopValue();
            Taint currentTaint = analyzedMethodConfig.getOutputTaint();
            analyzedMethodConfig.setOuputTaint(Taint.merge(returnTaint, currentTaint));
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException("empty stack before reference return", ex);
        }
        handleNormalInstruction(obj);

        for(TaintFrameAdditionalVisitor visitor : visitors) {
            try {
                visitor.visitReturn(methodGen, returnTaint, cpg);
            }
            catch (Throwable e) {
                LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
            }
        }
    }

    /**
     * Regroup the method invocations (INVOKEINTERFACE, INVOKESPECIAL,
     * INVOKESTATIC, INVOKEVIRTUAL)
     *
     * @param obj one of the invoke instructions
     */
    private void visitInvoke(InvokeInstruction obj) {
//        TaintFrame tf0 = getFrame();
        assert obj != null;
        try {
            TaintMethodConfig methodConfig = getMethodConfig(obj);
            ObjectType realInstanceClass = (methodConfig == null) ?
                    null : methodConfig.getOutputTaint().getRealInstanceClass();
            Taint taint = getMethodTaint(methodConfig);
            assert taint != null;
            if (FindSecBugsGlobalConfig.getInstance().isDebugTaintState()) {
                taint.setDebugInfo(obj.getMethodName(cpg) + "()"); //TODO: Deprecated debug info
            }

            taint.addSource(new UnknownSource(UnknownSourceType.RETURN,taint.getState()).setSignatureMethod(obj.getClassName(cpg).replace(".","/")+"."+obj.getMethodName(cpg)+obj.getSignature(cpg)));
            if (taint.isUnknown()) {
                taint.addLocation(getTaintLocation(), false);
            }
            taintMutableArguments(methodConfig, obj);
            transferTaintToMutables(methodConfig, taint); // adds variable index to taint too
            Taint taintCopy = new Taint(taint);
            // return type is not always the instance type
            taintCopy.setRealInstanceClass(realInstanceClass);

            TaintFrame tf = getFrame();

            int stackDepth = tf.getStackDepth();
            int nbParam = getNumWordsConsumed(obj);
            List<Taint> parameters = new ArrayList<>(nbParam);
            for(int i=0;i<Math.min(stackDepth,nbParam);i++) {
                parameters.add(new Taint(tf.getStackValue(i)));
            }
            int numProduce = getNumWordsProduced(obj);
            int numConsume = getNumWordsConsumed(obj);
//            taintCopy.setConstantValue("");
            //自定义内部field传递，数据结构
            String className = obj.getClassName(cpg);
//            if(ScanInfo.classList.contains(className)){
//                transferTaintfield(obj,taintCopy);
//            }else{
//                processCollection(obj,taintCopy);
//            }

//            transferTaintfield(obj,taintCopy);
            processCollection(obj,taintCopy);
//            generateConstantValue(obj,taintCopy);
//            generateRealType(obj,taintCopy);
            modelInstruction(obj,numConsume , numProduce, taintCopy);


            for(TaintFrameAdditionalVisitor visitor : visitors) {
                try {
                    visitor.visitInvoke(obj, methodGen, getFrame() , parameters, cpg);
                }
                catch (Throwable e) {
                    LOG.log(Level.SEVERE,"Error while executing "+visitor.getClass().getName(),e);
                }
            }

        } catch (Exception e) {
            String className = ClassName.toSlashedClassName(obj.getReferenceType(cpg).toString());
            String methodName = obj.getMethodName(cpg);
            String signature = obj.getSignature(cpg);

            throw new RuntimeException("Unable to call " + className + '.' + methodName + signature, e);
        }
    }

    public void generateRealType(InvokeInstruction obj,Taint taint) throws DataflowAnalysisException {
        String returnType =obj.getReturnType(cpg).toString();
//        int arg = methodGen.getArgumentNames().length;
        taint.setRealInstanceClass(new ObjectType(returnType));
//        int stackDep = getFrame().getStackDepth();
//        if(stackDep > 0){
//                Taint objTaint = getFrame().getStackValue(stackDep-1);
//                if(objTaint.getRealInstanceClassName() == null && objTaint.hasValidVariableIndex()){
//                    String className = obj.getClassName(cpg);
//                    int idx = objTaint.getVariableIndex();
//                    if(idx<arg) return;
//                    ObjectType ot = new ObjectType(className);
//                    getFrame().getValue(idx).setClassString(className);
////                    Taint t = getFrame().getValue(idx);
////                            t.setRealInstanceClass(ot);
////                    getFrame().getValue(objTaint.getVariableIndex()).setRealInstanceClass(new ObjectType(className));
//                }
//        }
    }



    //处理字符串传递
    private void generateConstantValue(InvokeInstruction obj, Taint taint) {
        String className = obj.getClassName(cpg);
        TaintFrame tf = getFrame();
        String mName = obj.getMethodName(cpg);

        //一般处理,相关字符串直接传递
        if (className.contains("java.lang.String")) {
            try {
                if (mName.contains("toString")) {
                    taint.setConstantValue(tf.getStackValue(0).getConstantValue());
                } else if (mName.contains("append")) {
                    int paramNum = obj.getArgumentTypes(cpg).length;
                    if (paramNum != 1) return;
                    String str0 = tf.getStackValue(0).getConstantValue();
                    String str1 = tf.getStackValue(1).getConstantValue();
                    if (str0 != null && str1 != null)
                        taint.setConstantValue(str1 + str0);
                    else
                        taint.setConstantValue("");
                } else {
                    taint.setConstantValue("");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }else if(className.equals("java.util.Properties") && mName.equals("getProperty")){
            if(tf.getStackDepth()<2) return;
            String realClass = "";
            try {
                String proFile = tf.getStackValue(1).getConstantValue();
                String key = tf.getStackValue(0).getConstantValue();
                realClass = PropritiesHelper.getPropritiesVaule(proFile,key);
                taint.setConstantValue(realClass);
            } catch (Exception e){
                e.printStackTrace();
            }
        }else if(className.equals("java.lang.Class")&&mName.equals("forName")){
            try{
                String rcName = tf.getStackValue(0).getConstantValue();
                if(rcName != null){
                    taint.setRealInstanceClass(new ObjectType(rcName));
                }
            }catch (Exception e){
                e.printStackTrace();
            }

        } else{
            if (obj.getArgumentTypes(cpg).length <= 1 && tf.getStackDepth() > 0) taint.setConstantValue(tf.getValue(0).getConstantValue());
        }
    }

    //处理数据结构
    private void processCollection(InvokeInstruction obj,Taint taint){
//        if(ScanInfo.scanSwitch == 0) return;
        String className = obj.getClassName(cpg).replace('.','/');
        String mn = obj.getMethodName(cpg);
        TaintFrame tt = getFrame();
        int stackDep = tt.getStackDepth();
        try{
            int varIdx = 0;
            //put,set,add这些操作对变量区操作，get状态对返回值操作
            if (className.contains("java/util")) {
                if(mn.contains("init")) return;
                if(stackDep>0 && tt.getValue(stackDep-1).hasValidVariableIndex()){
                    varIdx = tt.getStackValue(stackDep-1).getVariableIndex();
                    if(varIdx == -1) return;
                }
                if (className.contains("List")) {
                    tt.getValue(varIdx).initList();
                    tt.getStackValue(stackDep-1).initList();
                    taint.initList();
                    if ("add".equals(mn)) {
                        int paramNum = obj.getArgumentTypes(cpg).length;
                        switch (paramNum) {
                            case 1:
                                if (stackDep > 0){
                                    taint.setCollection(tt.getValue(varIdx));
                                    taint.innerList.add(tt.getTopValue().getState());
                                    tt.getValue(varIdx).innerList.add(tt.getTopValue().getState());
                                }
//                                    taint.innerList.add(tt.getTopValue().getState());
                                break;
                            case 2:
                                if (stackDep < 3) break;
                                String idxStr = tt.getStackValue(1).getConstantValue();
                                if (idxStr == null || Integer.parseInt(idxStr)<0 ) {
                                    break;
                                }
                                taint.setCollection(tt.getValue(varIdx));
                                taint.innerList.add(Integer.parseInt(idxStr), tt.getTopValue().getState());
                                tt.getValue(varIdx).innerList.add(Integer.parseInt(idxStr), tt.getTopValue().getState());
                                break;
                            default:
                                break;
                        }
                    } else if ("set".equals(mn)) {
                        if (obj.getArgumentTypes(cpg).length == 2 && stackDep > 2) {
                            String idxStr = tt.getStackValue(1).getConstantValue();
                            if (idxStr != null) {
                                taint.setCollection(tt.getStackValue(stackDep-1));
                                taint.innerList.set(Integer.parseInt(idxStr), tt.getTopValue().getState());
                                tt.getValue(varIdx).innerList.set(Integer.parseInt(idxStr), tt.getTopValue().getState());
                            }
                        }
                    } else if ("get".equals(mn)) {
                        if (taint.collectionIsVaild == true && stackDep > 1) {
                            String idx = tt.getTopValue().getConstantValue();
                            if (idx != null ) {
                                taint.setState(tt.getValue(varIdx).innerList.get(Integer.parseInt(idx)));
                            }
                        }
                    }else if("remove".equals(mn)){
                        ArrayList a = new ArrayList();
                        if(taint.collectionIsVaild == true && stackDep > 1){
                            String idxInner = tt.getStackValue(0).getConstantValue();
                            if(idxInner != null){
                                int idxInList = Integer.parseInt(idxInner);
                                tt.getValue(varIdx).innerList.remove(idxInList);
                            }
                        }
//                        tt.getSlotList().get(varIdx).innerList = null;
//                        tt.getSlotList().get(varIdx).collectionIsVaild = false;
                    }
                } else if (className.contains("Map")) {
                    tt.getValue(varIdx).initMap();
                    tt.getStackValue(stackDep-1).initMap();
                    taint.initMap();
                    if ("put".equals(mn)) {
                        if (obj.getArgumentTypes(cpg).length == 2 && stackDep > 2) {
                            String key = tt.getStackValue(1).getConstantValue();
                            if (key != null) {
                                tt.getValue(varIdx).innerMap.put(key, tt.getTopValue().getState());
                            } else {
                                tt.getValue(varIdx).innerMap = null;
                                tt.getValue(varIdx).collectionIsVaild = false;
                            }
                        }
                    } else if ("get".equals(mn)) {
                        if (stackDep > 1 && obj.getArgumentTypes(cpg).length == 1) {
                            String key = tt.getTopValue().getConstantValue();
                            if (taint.collectionIsVaild == true && taint.innerMap.containsKey(key)) {
                                taint.setState(taint.innerMap.get(key));
                            }
                        }
                    } else if ("remove".equals(mn)) {
                        if (obj.getArgumentTypes(cpg).length == 2 && stackDep > 2) {
                            String key = tt.getStackValue(1).getConstantValue();
                            if (key != null) {
                                tt.getSlotList().get(varIdx).innerMap.remove(key, tt.getTopValue().getState());
                            } else {
                                tt.getValue(varIdx).innerMap = null;
                                tt.getValue(varIdx).collectionIsVaild = false;
                            }
                        }
                    }else {
//                        tt.getSlotList().get(varIdx).innerMap = null;
//                        tt.getSlotList().get(varIdx).collectionIsVaild = false;
                    }
                }

            }

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    //污点传递
    private void transferTaintfield(InvokeInstruction obj,Taint taint) throws DataflowAnalysisException{
        //得到调用函数
        //得到参数状态
        //参数感染到字段
        //字段、参数->返回值
        //start
        //只对待扫描用户类进行分析
        String className = obj.getClassName(cpg).replace('.','/');
        String mn = obj.getMethodName(cpg);
        TaintFrame tt = getFrame();
        int stackDep = tt.getStackDepth();
        if(!ScanInfo.classList.contains(className)) return;
        String methname = obj.getClassName(cpg).replace('.','/')+'.'+obj.getMethodName(cpg)+obj.getSignature(cpg);
        Taint.State finalState = Taint.State.SAFE;
        //解决field、param->return
        Map<String,Set<String>> fdToRt = ScanInfo.fdToRt;
        Map<String,Set<Integer>> paToRt = ScanInfo.paToRt;
        //param->field
        Map<String, Map<Integer, Set<String>>> mp = ScanInfo.paToFd;
//        Map<String,Map<String,Set<Integer>>> mss = ScanInfo.paramToStaticField;
//            Taint t = methodConfig.getOutputTaint();
//            int mlen = Type.getArgumentTypes(obj.getSignature(cpg)).length;
        int len = obj.getArgumentTypes(cpg).length;

//            Set<Integer> pa = t.getParameters();
        Taint objTaint = null;
        try {
            int dep = tt.getStackDepth();
            //staticfield
            if(len==dep){
                objTaint = new Taint(Taint.State.UNKNOWN);
            }else{
                objTaint = tt.getStackValue(len);
            }
            //
            if (mp.containsKey(methname)) {
                Map<Integer, Set<String>> imap = mp.get(methname);

                //解决param->field
                for (int idx = 0; idx < len; idx++) {
                    if (imap.containsKey(idx)) {
                        Taint tmpt = tt.getStackValue(idx);
                        Taint.State s = tmpt.getState();
                        if (s != Taint.State.SAFE) {
                            for (String fi : imap.get(idx)) {
                                objTaint.fields.put(fi, s);
                            }
                        }
                    }
                }
            }
            if (paToRt.containsKey(methname)) {
                Set<Integer> mseti = paToRt.get(methname);
                //parame->return
                for (Integer idx : mseti) {
                    if (paToRt.containsKey(idx)) {
                        finalState = Taint.State.merge(finalState, tt.getStackValue(idx).getState());
                    }
                }
            }
            if (fdToRt.containsKey(methname)) {
                //field->return
                Set<String> msets = fdToRt.get(methname);
                for (String fd : msets) {
                    if (objTaint.fields.containsKey(fd)) {
                        finalState = Taint.State.merge(finalState, objTaint.fields.get(fd));
                    }
                }

            }
            if(len==dep){
                taint.fields.putAll(objTaint.fields);
            }else {
                taint.setState(finalState);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        //end
    }


    private TaintMethodConfig getMethodConfig(InvokeInstruction obj) {
        String signature = obj.getSignature(cpg);
        String returnType = getReturnType(signature);
        String className = getInstanceClassName(obj);
        String methodName = obj.getMethodName(cpg);
        String methodId = "." + methodName + signature;
        TaintMethodConfig config = taintConfig.getMethodConfig(getFrame(), methodDescriptor, className, methodId);
        if (config != null) {
            config = getConfigWithReplaceTags(config, className, methodName);
        }
        if (config != null && config.isConfigured()) {
            return config;
        }
        if (taintConfig.isClassTaintSafe(returnType)) {
            return TaintMethodConfig.SAFE_CONFIG;
        }
        if (config != null) {
            return config;
        }
        if (Const.CONSTRUCTOR_NAME.equals(methodName)
                && !taintConfig.isClassTaintSafe("L" + className + ";")) {
            try {
                int stackSize = getFrame().getNumArgumentsIncludingObjectInstance(obj, cpg);
                return TaintMethodConfig.getDefaultConstructorConfig(stackSize);
            } catch (DataflowAnalysisException ex) {
                throw new InvalidBytecodeException(ex.getMessage(), ex);
            }
        }
        return null;
    }

    private TaintMethodConfig getConfigWithReplaceTags(
            TaintMethodConfig config, String className, String methodName) {
        if (!"java/lang/String".equals(className)) {
            return config;
        }
        boolean isRegex = "replaceAll".equals(methodName);
        if (!isRegex && !"replace".equals(methodName)) {
            // not a replace method
            return config;
        }
        try {
            String toReplace = getFrame().getStackValue(1).getConstantValue();
            if (toReplace == null) {
                // we don't know the exact value
                return config;
            }
            Taint taint = config.getOutputTaint();
            for (Map.Entry<String, Taint.Tag> replaceTag : REPLACE_TAGS.entrySet()) {
                String tagString = replaceTag.getKey();
                if ((isRegex && toReplace.contains(tagString))
                        || toReplace.equals(tagString)) {
                    taint.addTag(replaceTag.getValue());
                }
            }
            TaintMethodConfig configCopy = new TaintMethodConfig(config);
            configCopy.setOuputTaint(taint);
            return configCopy;
        } catch (DataflowAnalysisException ex) {
            throw new InvalidBytecodeException(ex.getMessage(), ex);
        }
    }

    private String getInstanceClassName(InvokeInstruction invoke) {
        try {
            int instanceIndex = getFrame().getNumArgumentsIncludingObjectInstance(invoke, cpg) - 1;
            if (instanceIndex != -1) {
                assert instanceIndex < getFrame().getStackDepth();
                Taint instanceTaint = getFrame().getStackValue(instanceIndex);
                String className = instanceTaint.getRealInstanceClassName();
                if (className != null) {
                    return className;
                }
            }
        } catch (DataflowAnalysisException ex) {
            assert false : ex.getMessage();
        }
        String dottedClassName = invoke.getReferenceType(cpg).toString();
        return ClassName.toSlashedClassName(dottedClassName);
    }

    private static String getReturnType(String signature) {
        assert signature != null && signature.contains(")");
        return signature.substring(signature.indexOf(')') + 1);
    }

    private Taint getMethodTaint(TaintMethodConfig methodConfig) {
        if (methodConfig == null) {
            return getDefaultValue();
        }
        Taint taint = methodConfig.getOutputTaint();
        assert taint != null;
        assert taint != methodConfig.getOutputTaint() : "defensive copy not made";
        Taint taintCopy = new Taint(taint);
        if (taint.isUnknown() && taint.hasParameters()) {
            Taint merge = mergeTransferParameters(taint.getParameters());
            assert merge != null;
            // merge removes tags so we made a taint copy before
            taint = Taint.merge(Taint.valueOf(taint.getNonParametricState()), merge);
        }
        if (taint.isTainted()) {
            taint.addLocation(getTaintLocation(), true);
        }
        // don't add tags to safe values
        if (!taint.isSafe() && taintCopy.hasTags()) {
            for (Taint.Tag tag : taintCopy.getTags()) {
                taint.addTag(tag);
            }
        }
        if (taintCopy.isRemovingTags()) {
            for (Taint.Tag tag : taintCopy.getTagsToRemove()) {
                taint.removeTag(tag);
            }
        }
        return taint;
    }

    private void taintMutableArguments(TaintMethodConfig methodConfig, InvokeInstruction obj) {
        if (methodConfig != null && methodConfig.isConfigured()) {
            return;
        }
        Collection<Integer> mutableStackIndices = getMutableStackIndices(obj.getSignature(cpg));
        for (Integer index : mutableStackIndices) {
            assert index >= 0 && index < getFrame().getStackDepth();
            try {
                Taint stackValue = getFrame().getStackValue(index);
                Taint taint = Taint.merge(stackValue, getDefaultValue());
                if (stackValue.hasValidVariableIndex()) {
                    // set back the index removed during merging
                    taint.setVariableIndex(stackValue.getVariableIndex());
                }
                taint.setRealInstanceClass(stackValue.getRealInstanceClass());
                taint.addLocation(getTaintLocation(), false);
                getFrame().setValue(getFrame().getStackLocation(index), taint);
                setLocalVariableTaint(taint, taint);
            } catch (DataflowAnalysisException ex) {
                throw new InvalidBytecodeException("Not enough values on the stack", ex);
            }
        }
    }

    private Taint mergeTransferParameters(Collection<Integer> transferParameters) {
        assert transferParameters != null && !transferParameters.isEmpty();
        Taint taint = null;
        for (Integer transferParameter : transferParameters) {
            try {
                Taint value = getFrame().getStackValue(transferParameter);
                taint = Taint.merge(taint, value);
            } catch (DataflowAnalysisException ex) {
                throw new RuntimeException("Bad transfer parameter specification", ex);
            }
        }
        assert taint != null;
        return taint;
    }


    private void transferTaintToMutables(TaintMethodConfig methodConfig, Taint taint) {
        assert taint != null;
        if (methodConfig == null || !methodConfig.hasMutableStackIndices()) {
            return;
        }
        try {
            int stackDepth = getFrame().getStackDepth();
            for (Integer mutableStackIndex : methodConfig.getMutableStackIndices()) {
                assert mutableStackIndex >= 0;
                if (mutableStackIndex >= stackDepth) {
                    if (!Const.CONSTRUCTOR_NAME.equals(methodDescriptor.getName())
                            && !Const.STATIC_INITIALIZER_NAME.equals(methodDescriptor.getName())) {
                        assert false : "Out of bounds mutables in " + methodDescriptor + " Method Config: " + methodConfig.toString();
                    }
                    continue; // ignore if assertions disabled or if in constructor
                }
                Taint stackValue = getFrame().getStackValue(mutableStackIndex);
                TaintFrame tmptf = getFrame();
                Taint collectTaint = null;
                int idx = -1;
                if(stackValue.hasValidVariableIndex()){
                    idx = stackValue.getVariableIndex();
                    collectTaint = new Taint(getFrame().getValue(idx));
                    setLocalVariableTaint(taint, stackValue);
                    getFrame().getValue(idx).setCollection(collectTaint);
                }
                Taint taintCopy = new Taint(taint);
                // do not set instance to return values, can be different type
                taintCopy.setRealInstanceClass(stackValue.getRealInstanceClass());
                taintCopy.setConstantValue(getFrame().getStackValue(mutableStackIndex).getConstantValue());
                getFrame().setValue(getFrame().getStackLocation(mutableStackIndex), taintCopy);
            }
        } catch (DataflowAnalysisException ex) {
            assert false : ex.getMessage(); // stack depth is checked
        }
    }

    private void setLocalVariableTaint(Taint valueTaint, Taint indexTaint) {
        assert valueTaint != null && indexTaint != null;
        if (!indexTaint.hasValidVariableIndex()) {
            return;
        }
        int index = indexTaint.getVariableIndex();
        if (index >= getFrame().getNumLocals()) {
            assert false : "Out of bounds local variable index in " + methodDescriptor;
            return; // ignore if assertions disabled
        }
        valueTaint.setVariableIndex(index);
        getFrame().setValue(index, valueTaint);
    }

    /**
     * Push a value to the stack
     */
    private void pushSafe() {
        getFrame().pushValue(new Taint(Taint.State.SAFE));
    }

    /**
     * Push a value to the stack
     * The information passed will be viewable when the stack will be print. (See printStackState())
     * @param debugInfo String representation of the value push
     */
    private void pushSafeDebug(String debugInfo) {
        getFrame().pushValue(new Taint(Taint.State.SAFE).setDebugInfo(debugInfo));
    }

    private TaintLocation getTaintLocation() {
        return new TaintLocation(methodDescriptor, getLocation().getHandle().getPosition());
    }

    /**
     * This method must be called from outside at the end of the method analysis
     */
    public void finishAnalysis() {
        assert analyzedMethodConfig != null;
        Taint outputTaint = analyzedMethodConfig.getOutputTaint();
        if (outputTaint == null) {
            // void methods
            return;
        }
        String returnType = getReturnType(methodDescriptor.getSignature());
        if (taintConfig.isClassTaintSafe(returnType) && outputTaint.getState() != Taint.State.NULL) {
            // we do not have to store summaries with safe output
            return;
        }
        String realInstanceClassName = outputTaint.getRealInstanceClassName();
        if (returnType.equals("L" + realInstanceClassName + ";")) {
            // storing it in method summary is useless
            outputTaint.setRealInstanceClass(null);
            analyzedMethodConfig.setOuputTaint(outputTaint);
        }
        String className = methodDescriptor.getSlashedClassName();
        String methodId = "." + methodDescriptor.getName() + methodDescriptor.getSignature();
        if (analyzedMethodConfig.isInformative()
                || taintConfig.getSuperMethodConfig(className, methodId) != null) {
            String fullMethodName = className.concat(methodId);
            if (!taintConfig.containsKey(fullMethodName)) {
                // prefer configured summaries to derived
                taintConfig.put(fullMethodName, analyzedMethodConfig);
            }
        }
    }

}
