package com.h3xstream.findsecbugs.TransferParamFieldReturn;

import java.util.ArrayList;
import java.util.List;

public class ParamToField extends BaseTranser{
    private String methodName;
    private int fromIndex;
    private List<String> toFields;

    public ParamToField(String methodName){
        this.methodName = methodName;
        toFields = new ArrayList<String>();
    }

    public void setFromIndex(int idx){
        this.fromIndex = idx;
    }

    public void addFields(String fields){
        toFields.add(fields);
    }

    public List<String> getFields(){
        return toFields;
    }

}
