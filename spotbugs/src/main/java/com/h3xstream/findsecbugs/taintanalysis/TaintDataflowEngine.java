/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.taintanalysis;

import com.h3xstream.findsecbugs.FindSecBugsGlobalConfig;
import com.h3xstream.findsecbugs.TransferParamFieldReturn.MyselfConfig;
import edu.umd.cs.findbugs.ba.AnalysisContext;
import edu.umd.cs.findbugs.ba.CFG;
import edu.umd.cs.findbugs.ba.DepthFirstSearch;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.IMethodAnalysisEngine;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.io.IO;
import org.apache.bcel.generic.MethodGen;

import java.io.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Requests or creates needed objects and execute taint analysis,
 * extends taint summaries with analyzed methods
 * 
 * @author David Formanek (Y Soft Corporation, a.s.)
 */
public class TaintDataflowEngine implements IMethodAnalysisEngine<TaintDataflow> {

    private static final FindSecBugsGlobalConfig CONFIG = FindSecBugsGlobalConfig.getInstance();
    private static final Logger LOGGER = Logger.getLogger(TaintDataflowEngine.class.getName());
    private static final String TAINT_CONFIG_PATH = "taint-config/";
    private static final String[] TAINT_CONFIG_FILENAMES = {
        "android-taint-sql.txt",
        "collections.txt",
        "dropwizard.txt",
        "guava.txt",
        "java-ee.txt",
        "java-lang.txt",
        "java-net.txt",
        "jetty.txt",
        "logging.txt",
        "other.txt",
        "portlet.txt",
        "scala.txt",
        "sonarqube.txt",
        "struts2-taint.txt",
        "wicket.txt",
    };
    private static final String SAFE_ENCODERS_PATH = "safe-encoders/";
    private static final String[] SAFE_ENCODERS_FILENAMES = {
        "owasp.txt",
        "apache-commons.txt",
        "other.txt"
    };
    private final TaintConfig taintConfig = new TaintConfig();
    protected static Writer writer = null;
    private static List<TaintFrameAdditionalVisitor> visitors = new ArrayList<TaintFrameAdditionalVisitor>();


    static {
        if (CONFIG.isDebugOutputTaintConfigs()) {
            try {
                final String fileName = "derived-config.txt";
                writer = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(fileName), "utf-8"));
                // note: writer is not closed until the end
                LOGGER.info("Derived method configs will be output to " + fileName);
            } catch (UnsupportedEncodingException ex) {
                assert false : ex.getMessage();
            } catch (FileNotFoundException ex) {
                AnalysisContext.logError("File for derived configs cannot be created or opened", ex);
            }
        }
    }

    /**
     * Constructs the engine and loads all configured method summaries
     */
    public TaintDataflowEngine() {
        for (String path : TAINT_CONFIG_FILENAMES) {
            loadTaintConfig(TAINT_CONFIG_PATH.concat(path), true);
        }
        for (String path : SAFE_ENCODERS_FILENAMES) {
            loadTaintConfig(SAFE_ENCODERS_PATH.concat(path), true);
        }

        // Override the sensitive data taints
        loadTaintConfig(TAINT_CONFIG_PATH.concat("taint-sensitive-data.txt"), false);

        if (CONFIG.isTaintedSystemVariables()) {
            loadTaintConfig(TAINT_CONFIG_PATH.concat("tainted-system-variables.txt"), false);
            LOGGER.info("System variables are considered to be tainted");
        }
        //load myself config
        MyselfConfig.getMyselfConfig().setTaintConfig(taintConfig);
        String customConfigFile = CONFIG.getCustomConfigFile();
        if (customConfigFile != null && !customConfigFile.isEmpty()) {
            for (String configFile : customConfigFile.split(File.pathSeparator)) {
                addCustomConfig(configFile);
            }
        }
        if (!CONFIG.isTaintedMainArgument()) {
            LOGGER.info("The argument of the main method is not considered tainted");
        }
    }

    public static void registerAdditionalVisitor(TaintFrameAdditionalVisitor visitor) {
        visitors.add(visitor);
    }

    private void loadTaintConfig(String path, boolean checkRewrite) {
        assert path != null && !path.isEmpty();
        InputStream stream = null;
        try {
//            String st = this.getClass().getResource("").getPath();
//            String st2 = this.getClass().getResource("/").getPath();
//            URL u1 = this.getClass().getClassLoader().getResource("");

            stream = getClass().getClassLoader().getResourceAsStream(path);
            taintConfig.load(stream, checkRewrite);
        } catch (IOException ex) {
            assert false : ex.getMessage();
        } finally {
            IO.close(stream);
        }
    }
    
    private void addCustomConfig(String path) {
        InputStream stream = null;
        try {
            File file = new File(path);
            if (file.exists()) {
                stream = new FileInputStream(file);
            } else {
                stream = getClass().getClassLoader().getResourceAsStream(path);
            }
            if (stream == null) {
                String message = String.format("Could not add custom config. "
                        + "Neither file %s nor resource matching %s found.",
                        file.getAbsolutePath(), path);
                throw new IllegalArgumentException(message);
            }
            taintConfig.load(stream, false);
            LOGGER.log(Level.INFO, "Custom taint config loaded from {0}", path);
        } catch (IOException ex) {
            throw new RuntimeException("Cannot load custom taint config from " + path, ex);
        } finally {
            IO.close(stream);
        }
    }
    
    @Override
    public TaintDataflow analyze(IAnalysisCache cache, MethodDescriptor descriptor)
            throws CheckedAnalysisException {
        if(FindSecBugsGlobalConfig.getInstance().isDebugPrintInstructionVisited() || FindSecBugsGlobalConfig.getInstance().isDebugPrintInvocationVisited()) {
            System.out.println("==[ Method: "+descriptor.getName()+" ]==");
        }
        CFG cfg = cache.getMethodAnalysis(CFG.class, descriptor);
        DepthFirstSearch dfs = cache.getMethodAnalysis(DepthFirstSearch.class, descriptor);
        MethodGen methodGen = cache.getMethodAnalysis(MethodGen.class, descriptor);
        TaintAnalysis analysis = new TaintAnalysis(methodGen, dfs, descriptor, taintConfig, visitors);
        TaintDataflow flow = new TaintDataflow(cfg, analysis);
        flow.execute();
        analysis.finishAnalysis();
        if (CONFIG.isDebugOutputTaintConfigs() && writer != null) {
            TaintMethodConfig derivedConfig = taintConfig.get(getSlashedMethodName(methodGen));
            if (derivedConfig != null) {
                try {
                    writer.append(getSlashedMethodName(methodGen) + ":" + derivedConfig + "\n");
                    writer.flush();
                } catch (IOException ex) {
                    AnalysisContext.logError("Cannot write derived configs", ex);
                }
            }
        }
        return flow;
    }

    private static String getSlashedMethodName(MethodGen methodGen) {
        String methodNameWithSignature = methodGen.getName() + methodGen.getSignature();
        String slashedClassName = methodGen.getClassName().replace('.', '/');
        return slashedClassName + "." + methodNameWithSignature;
    }
    
    @Override
    public void registerWith(IAnalysisCache iac) {
        iac.registerMethodAnalysisEngine(TaintDataflow.class, this);
    }
}
