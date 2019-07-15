package com.h3xstream.findsecbugs.TransferParamFieldReturn;

import java.util.HashMap;
import java.util.Map;

public class BaseTranser {
    public static Map<String,FieldsToParam> fieldsToParam = new HashMap<String, FieldsToParam>();
    public static Map<String,FieldsToReturn> fieldsToReturn = new HashMap<String, FieldsToReturn>();
    public static Map<String,ParamToField> paramToField = new HashMap<String, ParamToField>();

}
