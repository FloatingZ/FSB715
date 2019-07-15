package com.h3xstream.findsecbugs;

import com.h3xstream.findsecbugs.taintanalysis.Taint;

import java.util.HashMap;
import java.util.Map;

public class MapHelper {
    private String name;
    private Map<String, Taint.State> statemap;
    public MapHelper(String name){
        this.name = name;
    }
    public void putstate(String key, Taint.State state){
        if(statemap == null)    statemap = new HashMap<String,Taint.State>();
        statemap.put(key,state);
    }
    public Taint.State getstate(String key){
        if(statemap == null) return null;
        else{
            return statemap.get(key);
        }
    }
}
