package com.h3xstream.findsecbugs;

import java.io.*;

public class WriteUtil {
    public static void writetest(String strtowrite){
        String path = "D:/mytes.txt";
        File f = new File(path);
        FileWriter fw = null;
        try{
            if(!f.exists()){
                f.createNewFile();
            }
            fw = new FileWriter(f,true);
            fw.append(strtowrite);
            fw.flush();
            fw.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
