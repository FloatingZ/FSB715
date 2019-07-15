package com.h3xstream.findsecbugs.TransferParamFieldReturn;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class PropritiesHelper {
    public static List<String> propritiesFileList = new ArrayList<String>();
    public static Map<String, Set<String>> jarToProper = new HashMap<String,Set<String>>();

    /**
     *
     * @param jarPath   jarfile that the properties file located
     * @return null
     */
    public static boolean getPropritiesFile(String jarPath){
        if(!(jarPath.endsWith(".jar")||jarPath.endsWith(".war")||jarPath.endsWith(".ear")))    return false;
        try {
            JarFile jf = new JarFile(jarPath);
            Enumeration<JarEntry> entrys = jf.entries();
            Set<String> s = new HashSet<String>();
            while(entrys.hasMoreElements()){
                JarEntry je = entrys.nextElement();
                String jn = je.getName();
                if(jn.endsWith(".properties"))    s.add(jn);
                if(jn.endsWith(".properties"))  propritiesFileList.add(jarPath+"!/"+jn);
            }
            jarToProper.put(jarPath,s);
        }catch (Exception e){
            e.printStackTrace();
        }
        return true;
    }

    /**
     *
     * @param file properties file name
     * @param key  key in properties
     * @return  the value for the key
     */
    public static String getPropritiesVaule(String file,String key){
        Set<String> ts = jarToProper.keySet();
        JarFile jarFile = null;
        String result = "";
        Properties properties = new Properties();
        for(String s:ts){
            Set<String> ms = jarToProper.get(s);
            for(String proName:ms){
                if(proName.contains(file)){
                    try{
                        jarFile = new JarFile(s);
                        InputStream is = jarFile.getInputStream(jarFile.getEntry(proName));
                        properties.load(is);
                        result += properties.getProperty(key);
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
        }
        return result;
    }
}
