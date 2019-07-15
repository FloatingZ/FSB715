package com.h3xstream.findsecbugs.injection.convert;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.bcel.OpcodeStackDetector;
import org.apache.bcel.Const;

import java.util.Arrays;
import java.util.List;

public class Unrestricted_FileUpload extends OpcodeStackDetector {
    private BugReporter bugReporter;

    String[] relevants = new String[]{
            "UploadItem", "CommonsMultipartFile", "MultipartFile",
            "MockMultipartFile", "FileItem", "DiskFileItem",
            "FileItem", "DefaultFileItem", "CommonsMultipartResolver",
            "MultipartRequest", "Part",
            "HttpServletRequest", "HttpServletRequestWrapper",
            "ServletRequest", "ServletRequestWrapper" };

    String[] validators = new String[]{
            "getSize", "getFileSize", "getName",
            "getContentType", "getSubmittedFileName"};

    String[] dataAccess = new String[]{"transferTo", "write","getData", "get", "getFile", "getInputStream",
            "getOutputStream", "getFileData",};


    List<String> rele;
    List<String> vail;
    List<String> access;

    public Unrestricted_FileUpload(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
        rele = Arrays.asList(relevants);
        vail = Arrays.asList(validators);
        access = Arrays.asList(dataAccess);

    }



    @Override
    public void sawOpcode(int seen) {
        int startIf = 0;
        int endIf = 0;
        int apiLoc = 0;
        int gotoTarget = 0;
        int accessLoca = 0;
        int vailLoca = 0;
        if(seen == Const.IFEQ){
            startIf = getPC();
            endIf = getBranchTarget();
        }
        if(seen == Const.GOTO){
            gotoTarget = getBranchTarget();
            if(gotoTarget>endIf)    endIf = gotoTarget;
        }
        if(seen == Const.INVOKEVIRTUAL || seen == Const.INVOKESPECIAL){
            if(vail.contains(getNameConstantOperand())) vailLoca = getPC();
            if(rele.contains(getClassConstantOperand())&&access.contains(getNameConstantOperand())){
                accessLoca = getPC();
                if(!((accessLoca>startIf && accessLoca<endIf)&&(vailLoca>startIf && vailLoca<endIf))){
                    bugReporter.reportBug(new BugInstance("Unrestricted_FileUpload", Priorities.NORMAL_PRIORITY).addClassAndMethod(this).addSourceLine(this)
                    );
                }
            }

        }
    }
}
