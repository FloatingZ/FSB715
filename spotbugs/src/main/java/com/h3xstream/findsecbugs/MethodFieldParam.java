package com.h3xstream.findsecbugs;

import org.apache.bcel.classfile.Field;

import java.util.HashMap;
import java.util.Map;

public class MethodFieldParam {
    private static Map<String, Field[]> classField = new HashMap<String,Field[]>();

    public static void putFields(String meth,Field[] f){
        if(classField.containsKey(meth)){
            return;
        }
        classField.put(meth,f);
    }

    public static Field[] getFieldsFromName(String met){
        if(classField.containsKey(met)){
            return classField.get(met);
        }else{
            return null;
        }
    }
}

