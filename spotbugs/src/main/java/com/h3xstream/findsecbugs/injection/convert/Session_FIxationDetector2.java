package com.h3xstream.findsecbugs.injection.convert;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.SourceLineAnnotation;
import edu.umd.cs.findbugs.bcel.OpcodeStackDetector;
import org.apache.bcel.Const;

public class Session_FIxationDetector2 extends OpcodeStackDetector {
    private BugReporter bugReporter;
    private boolean creatSession = false;
    private boolean changeSession = false;
    SourceLineAnnotation sourceLine;
    BugInstance bugInstance;

    public Session_FIxationDetector2(BugReporter bugReporter){
        this.bugReporter = bugReporter;
    }

    @Override
    public void sawOpcode(int seen) {
        if(seen == Const.INVOKESPECIAL|| seen == Const.INVOKESTATIC || seen == Const.INVOKEVIRTUAL){
            if(getNameConstantOperand().toLowerCase().contains("getsession"))   {
                creatSession = true;
                bugInstance = new BugInstance(this,"Seesion", Priorities.NORMAL_PRIORITY).addClassAndMethod(this).addCalledMethod(this)
                        .addSourceLine(this);
            }
            if(getNameConstantOperand().toLowerCase().contains("changeidsession")) changeSession = true;
        }
    }


    @Override
    public void report(){
        if(creatSession == true && changeSession == false){
            bugReporter.reportBug(bugInstance);
        }
    }



}
