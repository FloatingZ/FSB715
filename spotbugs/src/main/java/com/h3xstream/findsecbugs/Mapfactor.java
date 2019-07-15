package com.h3xstream.findsecbugs;

import com.h3xstream.findsecbugs.taintanalysis.Taint;

import java.util.HashMap;
import java.util.Map;

public class Mapfactor {
    private static Map<String, Taint.State> stateMap = new HashMap<String,Taint.State>();
    public static boolean changetag = false;
    public static boolean issafe = false;
    public static Taint.State state = null;

    public static Taint.State getState(String key){
        Taint.State mstate = stateMap.get(key);
        if(mstate != null)  return mstate;
        else    return null;
    }

    public static void putState(String key,Taint.State state){
        stateMap.put(key,state);
    }
}
