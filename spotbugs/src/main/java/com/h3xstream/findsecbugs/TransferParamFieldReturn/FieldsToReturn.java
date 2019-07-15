package com.h3xstream.findsecbugs.TransferParamFieldReturn;

import java.util.ArrayList;
import java.util.List;

public class FieldsToReturn {
    private String methodName;
    private List<String> from ;

    public FieldsToReturn(String methodName){
        this.methodName = methodName;
        from= new ArrayList<String>();
    }
    public void addField(String filedName){
        if(!from.contains(filedName)) from.add(filedName);
    }

}
