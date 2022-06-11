import os
import sys
import subprocess
from mobsftester import *
import time
import xmltodict
import json

# pylint: disable=pointless-string-statement
"""
Program that handles running the following tools, saving outputs in a subsequent folder:

    1. apkid
    2. apkleaks
    3. mobsf
    4. flowdroid
    5. d2j-dex2jar + dependency-check on the newly created jar file

'"""

def run_apkid(_name):
    """
    Runs apkid on the apk file.
    """
    print(f"Running apkid on apps/{_name}")

    # Run apkid
    apkid_cmd = f"apkid -v apps/{_name} > apkid_output/{_name[:-4]}_apkid.txt"

    try:
        subprocess.run(apkid_cmd, shell = True, timeout = 60, check = True)
    except subprocess.TimeoutExpired:
        
        # Add a new line to the timeouts.txt file
        with open("timeouts.txt", "a") as f:
            f.write(f"apkid: {_name}\n")

        print("TIMEOUT + apkid timed out + TIMEOUT on the following app: " + _name)
        return

def run_apkleaks(_name):
    """
    Runs apkleaks on the apk file.
    """
    print(f"Running apkleaks on apps/{_name}")

    # Run apkleaks
    apkleaks_cmd = f"apkleaks -f apps/{_name} -o apkleaks_output/{_name[:-4]}_apkleaks.txt"

    try:
        subprocess.run(apkleaks_cmd, shell = True, timeout = 150, check = True)
    except subprocess.TimeoutExpired:

        # Add a new line to the timeouts.txt file
        with open("timeouts.txt", "a") as f:
            f.write(f"apkleaks: {_name}\n")

        print("TIMEOUT + apkleaks timed out + TIMEOUT on the following app: " + _name)
        return

def run_d_check(_name):
    """
    Runs dependency-check on the jar file.
    """
    print(f"Running dex2jar and dependency-check on {_name}")


    try:
        # Run dex2jar
        d2j_cmd = f"d2j-dex2jar apps/{_name} -o temp_jar/{_name[:-4]}.jar"
        subprocess.run(d2j_cmd, shell = True, timeout = 20, check = True)

        # Run dependency-check
        d_check_cmd_json = f"dependency-check -s temp_jar/{_name[:-4]}.jar -f JSON -o dependencycheck_output/{_name[:-4]}"
        # had to add -n so that no update is done, this got me a lot of errors
        subprocess.run(d_check_cmd_json, shell = True, timeout = 40, check = True)
        
        # d_check_cmd_html = f"dependency-check -s temp_jar/{_name[:-4]}.jar -f HTML -o dependencycheck_output/{_name[:-4]}"
        # subprocess.run(d_check_cmd_html, shell = True, timeout = 60, check = True)

    except subprocess.TimeoutExpired:

        # Add a new line to the timeouts.txt file
        with open("timeouts.txt", "a") as f:
            f.write(f"d_check: {_name}\n")

        print("TIMEOUT + dependency-check timed out + TIMEOUT on the following app: " + _name)
        return

def run_flowdroid(_name):
    """
    Runs flowdroid on the apk file.
    """
    print(f"Running flowdroid on {_name}")

    flow_droid_folder = "/Users/vlad/Desktop/THESIS/FlowDroid-2.10"

    # Run flowdroid
    # flowdroid -a ../bachelor_thesis/apps/cam3.apk -p /Users/vlad/Library/Android/sdk/platforms -s soot-infoflow-android/SourcesAndSinks.txt
    flowdroid_cmd = f"java -jar {flow_droid_folder}/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar -s {flow_droid_folder}/soot-infoflow-android/SourcesAndSinks.txt -a apps/{_name} -p /Users/vlad/Library/Android/sdk/platforms -o flowdroid_output/{_name[:-4]}_flowdroid.xml"

    try:
        subprocess.run(flowdroid_cmd, shell = True, timeout = 150, check = True)
    except subprocess.TimeoutExpired:
        
        # Add a new line to the timeouts.txt file
        with open("timeouts_150.txt", "a") as f:
            f.write(f"flowdroid: {_name}\n")

        print("TIMEOUT + flowdroid timed out + TIMEOUT on the following app: " + _name)
        return
    

def run_mobsf(_name):
    """
    Runs mobsf on the apk file.
    """
    RESP = upload(f"apps/{_name}")
    scan(RESP)
    json_resp(RESP)
    pdf(RESP, _name[:-4])

def create_output_folders():
    """
    Creates the output folders.
    """
    if not os.path.exists("apkid_output"):
        os.makedirs("apkid_output")
    if not os.path.exists("apkleaks_output"):
        os.makedirs("apkleaks_output")
    if not os.path.exists("mobsf_output"):
        os.makedirs("mobsf_output")
    if not os.path.exists("flowdroid_output"):
        os.makedirs("flowdroid_output")
    if not os.path.exists("temp_jar"):
        os.makedirs("temp_jar")
    if not os.path.exists("dependencycheck_output"):
        os.makedirs("dependencycheck_output")

def parse_apkid_output(_output):
    """
    The apkid output can look like either of these cases:

    1. 
    [+] APKiD 2.1.3 :: from RedNaga :: rednaga.io
    [*] apps/installer109.apk!classes.dex
    |-> anti_vm : Build.FINGERPRINT check, Build.MANUFACTURER check
    |-> compiler : r8

    2. 
    [+] APKiD 2.1.3 :: from RedNaga :: rednaga.io
    [*] apps/installer103.apk!classes.dex
    |-> anti_vm : Build.FINGERPRINT check, Build.MANUFACTURER check
    |-> compiler : r8
    [*] apps/installer103.apk!classes2.dex
    |-> compiler : r8 without marker (suspicious)

    3.
    [+] APKiD 2.1.3 :: from RedNaga :: rednaga.io
    [*] apps/installer147.apk!classes.dex
    |-> anti_vm : Build.MANUFACTURER check
    |-> compiler : unknown (please file detection issue!)

    We need to extract the types of compilers, anti_vms, etc. for the first entry, namely the one for classes.dex;

    We will take the apkid output as our input, and hence the final output should be stored in a mapping as so:

    {file_name: "installer109.apk", anti_vm: ["Build.FINGERPRINT check", "Build.MANUFACTURER check"], compiler: "r8"}
    """
    result = {"file_name": _output}

    with open("apkid_output/" + _output[:-4] + "_apkid.txt", "r") as f:
        for line in f:
            # print(line)
            if "anti_vm" in line:
                anti_vm = line.split("anti_vm : ")[1].strip()
                # transform Build.FINGERPRINT check, Build.MANUFACTURER check into array
                anti_vm = anti_vm.split(", ")
                # print(anti_vm)

                result["anti_vm"] = anti_vm
            if "compiler" in line:
                compiler = line.split("compiler : ")[1].strip()
                result["compiler"] = compiler

    return result

def parse_apkleaks_output(_output):
    """
    The apkid output can look like either of these cases:

    1. 
    [IP_Address]
    - 19.3.1.1
    - 35.1.1.1

    [LinkFinder]
    - /proc/self/fd/
    - activity_choser_model_history.xml
    - http://schemas.android.com/apk/res/android
    - http://xmlpull.org/v1/doc/features.html#indent-output
    - share_history.xml

    [IP_Address]
    - 19.3.1.1
    - 35.1.1.1

    [LinkFinder]
    - /proc/self/fd/
    - activity_choser_model_history.xml
    - http://schemas.android.com/apk/res/android
    - http://xmlpull.org/v1/doc/features.html#indent-output
    - share_history.xml

    We need to extract each type of finding, for example: `[IP_Address]`, `[LinkFinder]`, `[Amazon_AWS_S3_Bucket]`, etc.

    We will take the apkleaks output as our input, and hence the final output should be stored in a mapping as so:

    {file_name: "installer109.apk", IP_Address: ["19.3.1.1","35.1.1.1"], LinkFinder: ["/...,/Up", "/index.html", "/mnt/sdcard", "/png8?app_id="], etc..}
    """
    result = {"file_name": _output}

    with open("apkleaks_output/" + _output[:-4] + "_apkleaks.txt", "r") as f:
        finding = ""
        for i, line in enumerate(f):
            # if the line contains `[name_of_finding]`, then we know we are in a new finding
            if line[0] == "[":
                finding = line.strip("[]\n")
                result[finding] = []
            else:
                # otherwise, we are inside a finding, so while we are in a finding, we will keep appending to it
                if finding:
                    # print(line)
                    line = line.strip("- \n")
                    if len(line) > 0:
                        result[finding].append(line)

    return result

def parse_flowdroid_output(_output):
    """
    The flowdroid output is in xml format and can look like either of these cases:

    1. 
    <?xml version="1.0" encoding="UTF-8"?><DataFlowResults FileFormatVersion="102" TerminationState="Success"><Results><Result><Sink Statement="virtualinvoke $r5.&lt;java.io.OutputStream: void write(byte[],int,int)&gt;(r3, 0, $i1)" Method="&lt;protect.babymonitor.MonitorActivity: void serviceConnection(java.net.Socket)&gt;"><AccessPath Value="$i1" Type="int" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$i1 = virtualinvoke r2.&lt;android.media.AudioRecord: int read(byte[],int,int)&gt;(r3, 0, $i0)" Method="&lt;protect.babymonitor.MonitorActivity: void serviceConnection(java.net.Socket)&gt;"><AccessPath Value="$i1" Type="int" TaintSubFields="true"></AccessPath></Source></Sources></Result></Results><PerformanceData><PerformanceEntry Name="CallgraphConstructionSeconds" Value="1"></PerformanceEntry><PerformanceEntry Name="TotalRuntimeSeconds" Value="1"></PerformanceEntry><PerformanceEntry Name="MaxMemoryConsumption" Value="153"></PerformanceEntry><PerformanceEntry Name="SourceCount" Value="1"></PerformanceEntry><PerformanceEntry Name="SinkCount" Value="38"></PerformanceEntry></PerformanceData></DataFlowResults>
    
    2.<?xml version="1.0" encoding="UTF-8"?><DataFlowResults FileFormatVersion="102" TerminationState="DataFlowOutOfMemory"><Results><Result><Sink Statement="virtualinvoke $r2.&lt;android.content.Context: void startActivities(android.content.Intent[])&gt;($r0)" Method="&lt;androidx.core.content.ContextCompat: boolean startActivities(android.content.Context,android.content.Intent[],android.os.Bundle)&gt;"><AccessPath Value="$r2" Type="android.content.Context" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$d0 = virtualinvoke $r1.&lt;android.location.Location: double getLatitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d0" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d1 = virtualinvoke $r1.&lt;android.location.Location: double getLongitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d1" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d0 = virtualinvoke $r1.&lt;android.location.Location: double getLatitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d0" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d1 = virtualinvoke $r1.&lt;android.location.Location: double getLongitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d1" Type="double" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="staticinvoke &lt;android.util.Log: int d(java.lang.String,java.lang.String)&gt;($r6, $r9)" Method="&lt;com.kalab.chess.enginesupport.ChessEngineResolver: java.util.List resolveEnginesForPackage(java.util.List,android.content.pm.ResolveInfo,java.lang.String)&gt;"><AccessPath Value="$r9" Type="java.lang.String" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$r4 = virtualinvoke $r3.&lt;android.content.pm.PackageManager: java.util.List queryIntentActivities(android.content.Intent,int)&gt;($r11, 128)" Method="&lt;com.kalab.chess.enginesupport.ChessEngineResolver: java.util.List resolveEngines()&gt;"><AccessPath Value="$r4" Type="java.util.List" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="staticinvoke &lt;android.util.Log: int d(java.lang.String,java.lang.String)&gt;(&quot;NotifManCompat&quot;, $r12)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void updateListenerMap()&gt;"><AccessPath Value="$r12" Type="java.lang.String" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$r6 = virtualinvoke $r4.&lt;android.content.pm.PackageManager: java.util.List queryIntentServices(android.content.Intent,int)&gt;($r5, 0)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void updateListenerMap()&gt;"><AccessPath Value="$r6" Type="java.util.List" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="staticinvoke &lt;android.util.Log: int v(java.lang.String,java.lang.String)&gt;(&quot;FragmentManager&quot;, $r8)" Method="&lt;androidx.fragment.app.FragmentManagerImpl: void moveToState(androidx.fragment.app.Fragment,int,int,int,boolean)&gt;"><AccessPath Value="$r8" Type="java.lang.String" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$d0 = virtualinvoke $r1.&lt;android.location.Location: double getLatitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d0" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d0 = virtualinvoke $r1.&lt;android.location.Location: double getLatitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d0" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d1 = virtualinvoke $r1.&lt;android.location.Location: double getLongitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d1" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d1 = virtualinvoke $r1.&lt;android.location.Location: double getLongitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d1" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d0 = virtualinvoke $r1.&lt;android.location.Location: double getLatitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d0" Type="double" TaintSubFields="true"></AccessPath></Source><Source Statement="$d1 = virtualinvoke $r1.&lt;android.location.Location: double getLongitude()&gt;()" Method="&lt;androidx.appcompat.app.TwilightManager: void updateState(android.location.Location)&gt;"><AccessPath Value="$d1" Type="double" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="staticinvoke &lt;android.util.Log: int d(java.lang.String,java.lang.String)&gt;(&quot;NotifManCompat&quot;, $r12)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void updateListenerMap()&gt;"><AccessPath Value="$r12" Type="java.lang.String" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$r6 = virtualinvoke $r4.&lt;android.content.pm.PackageManager: java.util.List queryIntentServices(android.content.Intent,int)&gt;($r5, 0)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void updateListenerMap()&gt;"><AccessPath Value="$r6" Type="java.util.List" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="$z0 = virtualinvoke $r4.&lt;android.content.Context: boolean bindService(android.content.Intent,android.content.ServiceConnection,int)&gt;($r2, r0, 33)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: boolean ensureServiceBound(androidx.core.app.NotificationManagerCompat$SideChannelManager$ListenerRecord)&gt;"><AccessPath Value="r0" Type="androidx.core.app.NotificationManagerCompat$SideChannelManager" TaintSubFields="true"><Fields><Field Value="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: java.util.Map mRecordMap&gt;" Type="java.util.Map"></Field><Field Value="&lt;java.util.Map: java.lang.Object[] values&gt;" Type="java.lang.Object[]"></Field></Fields></AccessPath></Sink><Sources><Source Statement="$r6 = virtualinvoke $r4.&lt;android.content.pm.PackageManager: java.util.List queryIntentServices(android.content.Intent,int)&gt;($r5, 0)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void updateListenerMap()&gt;"><AccessPath Value="$r6" Type="java.util.List" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="staticinvoke &lt;android.util.Log: int d(java.lang.String,java.lang.String)&gt;($r4, $r6)" Method="&lt;com.kalab.chess.enginesupport.ChessEngineResolver: java.util.List resolveEnginesForPackage(java.util.List,android.content.pm.ResolveInfo,java.lang.String)&gt;"><AccessPath Value="$r6" Type="java.lang.String" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$r4 = virtualinvoke $r3.&lt;android.content.pm.PackageManager: java.util.List queryIntentActivities(android.content.Intent,int)&gt;($r11, 128)" Method="&lt;com.kalab.chess.enginesupport.ChessEngineResolver: java.util.List resolveEngines()&gt;"><AccessPath Value="$r4" Type="java.util.List" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="staticinvoke &lt;android.util.Log: int d(java.lang.String,java.lang.String)&gt;(&quot;NotifManCompat&quot;, $r6)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void processListenerQueue(androidx.core.app.NotificationManagerCompat$SideChannelManager$ListenerRecord)&gt;"><AccessPath Value="$r6" Type="java.lang.String" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$r6 = virtualinvoke $r4.&lt;android.content.pm.PackageManager: java.util.List queryIntentServices(android.content.Intent,int)&gt;($r5, 0)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void updateListenerMap()&gt;"><AccessPath Value="$r6" Type="java.util.List" TaintSubFields="true"></AccessPath></Source></Sources></Result><Result><Sink Statement="staticinvoke &lt;android.util.Log: int w(java.lang.String,java.lang.String)&gt;(&quot;NotifManCompat&quot;, $r6)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void scheduleListenerRetry(androidx.core.app.NotificationManagerCompat$SideChannelManager$ListenerRecord)&gt;"><AccessPath Value="$r6" Type="java.lang.String" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$r6 = virtualinvoke $r4.&lt;android.content.pm.PackageManager: java.util.List queryIntentServices(android.content.Intent,int)&gt;($r5, 0)" Method="&lt;androidx.core.app.NotificationManagerCompat$SideChannelManager: void updateListenerMap()&gt;"><AccessPath Value="$r6" Type="java.util.List" TaintSubFields="true"></AccessPath></Source></Sources></Result></Results><PerformanceData><PerformanceEntry Name="CallgraphConstructionSeconds" Value="19"></PerformanceEntry><PerformanceEntry Name="TaintPropagationSeconds" Value="64"></PerformanceEntry><PerformanceEntry Name="PathReconstructionSeconds" Value="10"></PerformanceEntry><PerformanceEntry Name="TotalRuntimeSeconds" Value="95"></PerformanceEntry><PerformanceEntry Name="MaxMemoryConsumption" Value="2847"></PerformanceEntry><PerformanceEntry Name="SourceCount" Value="11"></PerformanceEntry><PerformanceEntry Name="SinkCount" Value="257"></PerformanceEntry></PerformanceData></DataFlowResults>
     
    """
    result = {"file_name": _output}

    with open("flowdroid_output/" + _output[:-4] + "_flowdroid.xml", "rb") as f:

        parsed_file = xmltodict.parse(f)

        # After the file is parsed, it looks like this:
        return parsed_file
        """
        {
            'DataFlowResults': {
                '@FileFormatVersion': '102', 
                '@TerminationState': 'DataFlowOutOfMemory', 
                'Results': {
                    'Result': [
                        {
                            'Sink': {
                                '@Statement': 'staticinvoke <android.util.Log: int d(java.lang.String,java.lang.String)>("FragmentManager", $r3)', 
                                '@Method': '<androidx.fragment.app.q0: void C0(androidx.fragment.app.o,int)>', 
                                'AccessPath': {
                                    '@Value': '$r3', 
                                    '@Type': 'java.lang.String', 
                                    '@TaintSubFields': 'true'
                                }
                            }, 
                            'Sources': 
                            {
                                'Source': [
                                    {
                                        '@Statement': '$d1 = virtualinvoke $r1.<android.location.Location: double getLongitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {
                                            '@Value': '$d1', 
                                            '@Type': 'double', 
                                            '@TaintSubFields': 'true'
                                        }
                                    },
                                    {
                                        '@Statement': '$d1 = virtualinvoke $r1.<android.location.Location: double getLongitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {
                                            '@Value': '$d1', '@Type': 'double', '@TaintSubFields': 'true'
                                        }
                                    }, 
                                    {
                                        '@Statement': '$d1 = virtualinvoke $r1.<android.location.Location: double getLongitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': 
                                        {
                                            '@Value': '$d1', 
                                            '@Type': 'double', 
                                            '@TaintSubFields': 'true'
                                        }
                                    }, 
                                    {
                                        '@Statement': '$d0 = virtualinvoke $r1.<android.location.Location: double getLatitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {
                                            '@Value': '$d0', '@Type': 'double', '@TaintSubFields': 'true'
                                        }
                                    }, 
                                    {
                                        '@Statement': '$d0 = virtualinvoke $r1.<android.location.Location: double getLatitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {
                                            '@Value': '$d0', '@Type': 'double', '@TaintSubFields': 'true'
                                        }
                                    }, 
                                    {
                                        '@Statement': '$d0 = virtualinvoke $r1.<android.location.Location: double getLatitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {
                                            '@Value': '$d0', '@Type': 'double', '@TaintSubFields': 'true'
                                        }
                                    }
                                ]
                            }
                        }, 
                        {
                            'Sink': {
                                '@Statement': 'virtualinvoke $r2.<android.os.Bundle: void putAll(android.os.Bundle)>($r3)', 
                                '@Method': '<androidx.savedstate.d: void c(android.os.Bundle)>', 
                                'AccessPath': {'@Value': '$r3', '@Type': 'android.os.Bundle', '@TaintSubFields': 'true'}
                            }, 
                            'Sources': {
                                'Source': [
                                    {
                                        '@Statement': '$d1 = virtualinvoke $r1.<android.location.Location: double getLongitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {'@Value': '$d1', '@Type': 'double', '@TaintSubFields': 'true'}
                                    }, 
                                    {
                                        '@Statement': '$d1 = virtualinvoke $r1.<android.location.Location: double getLongitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {'@Value': '$d1', '@Type': 'double', '@TaintSubFields': 'true'}
                                    }, 
                                    {
                                        '@Statement': '$d0 = virtualinvoke $r1.<android.location.Location: double getLatitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {'@Value': '$d0', '@Type': 'double', '@TaintSubFields': 'true'}
                                    }, 
                                    {
                                        '@Statement': '$d0 = virtualinvoke $r1.<android.location.Location: double getLatitude()>()', 
                                        '@Method': '<androidx.appcompat.app.r1: void f(android.location.Location)>', 
                                        'AccessPath': {'@Value': '$d0', '@Type': 'double', '@TaintSubFields': 'true'}
                                    }
                                ]
                            }
                        }
                    ]
                },
                'PerformanceData': {
                    'PerformanceEntry': [
                        {
                            '@Name': 'CallgraphConstructionSeconds', '@Value': '12'
                        }, 
                        {
                            '@Name': 'TaintPropagationSeconds', '@Value': '110'
                        }, {
                            '@Name': 'PathReconstructionSeconds', '@Value': '12'
                        }, {
                            '@Name': 'TotalRuntimeSeconds', '@Value': '137'
                        }, {
                            '@Name': 'MaxMemoryConsumption', '@Value': '3055'
                        }, {
                            '@Name': 'SourceCount', '@Value': '7'
                        }, {
                            '@Name': 'SinkCount', '@Value': '129'
                        }
                    ]
                }
            }
        }
        """

        # or 
        """
        {
            'DataFlowResults': {
                '@FileFormatVersion': '102', 
                '@TerminationState': 
                'Success', 
                'PerformanceData': {
                    'PerformanceEntry': [
                        {
                            '@Name': 'CallgraphConstructionSeconds', 
                            '@Value': '1'
                        }, {
                            '@Name': 'TotalRuntimeSeconds', 
                            '@Value': '1'
                        }, {
                            '@Name': 'MaxMemoryConsumption', 
                            '@Value': '146'
                        }
                    ]
                }
            }
        }
        """

def parse_dependencycheck_output(_output):
    """
    The output of the dependency checker is a JSON file, and it has the following format:

    {
    "reportSchema": "1.1",
    "scanInfo": {
        "engineVersion": "7.1.0",
        "dataSource": [
            {
                "name": "NVD CVE Checked",
                "timestamp": "2022-05-26T11:37:35"
            },
            {
                "name": "NVD CVE Modified",
                "timestamp": "2022-05-26T07:00:01"
            },
            {
                "name": "VersionCheckOn",
                "timestamp": "2022-05-21T17:25:15"
            }
        ]
    },
    "projectInfo": {
        "name": "",
        "reportDate": "2022-05-26T09:56:10.497377Z",
        "credits": {
            "NVD": "This report contains data retrieved from the National Vulnerability Database: http://nvd.nist.gov",
            "NPM": "This report may contain data retrieved from the NPM Public Advisories: https://www.npmjs.com/advisories",
            "RETIREJS": "This report may contain data retrieved from the RetireJS community: https://retirejs.github.io/retire.js/",
            "OSSINDEX": "This report may contain data retrieved from the Sonatype OSS Index: https://ossindex.sonatype.org"
        }
    },
    "dependencies": [
        {
            "isVirtual": false,
            "fileName": "gps2.jar",
            "filePath": "\/Users\/vlad\/Desktop\/THESIS\/bachelor_thesis\/temp_jar\/gps2.jar",
            "md5": "463236bdcd964de89428a782791d5e91",
            "sha1": "16741cb8b3a0bc697ec909ae672ac2869b024ddf",
            "sha256": "6f82751b31657db6ff9fa97d10ce937d329005e1ffc810e44a5765c6d63dc4d5",
            "evidenceCollected": {
                "vendorEvidence": [
                    {
                        "type": "vendor",
                        "confidence": "HIGH",
                        "source": "file",
                        "name": "name",
                        "value": "gps2"
                    },
                    {
                        "type": "vendor",
                        "confidence": "LOW",
                        "source": "jar",
                        "name": "package name",
                        "value": "apache"
                    },
                    {
                        "type": "vendor",
                        "confidence": "LOW",
                        "source": "jar",
                        "name": "package name",
                        "value": "cordova"
                    }
                ],
                "productEvidence": [
                    {
                        "type": "product",
                        "confidence": "HIGH",
                        "source": "file",
                        "name": "name",
                        "value": "gps2"
                    },
                    {
                        "type": "product",
                        "confidence": "LOW",
                        "source": "jar",
                        "name": "package name",
                        "value": "cordova"
                    }
                ],
                "versionEvidence": [
                    {
                        "type": "version",
                        "confidence": "MEDIUM",
                        "source": "file",
                        "name": "name",
                        "value": "gps2"
                    },
                    {
                        "type": "version",
                        "confidence": "MEDIUM",
                        "source": "file",
                        "name": "version",
                        "value": "2"
                    }
                ]
            },
            "vulnerabilityIds": [
                {
                    "id": "cpe:2.3:a:apache:cordova:2:*:*:*:*:*:*:*",
                    "confidence": "LOW",
                    "url": "https:\/\/nvd.nist.gov\/vuln\/search\/results?form_type=Advanced&results_type=overview&search_type=all&cpe_vendor=cpe%3A%2F%3Aapache&cpe_product=cpe%3A%2F%3Aapache%3Acordova&cpe_version=cpe%3A%2F%3Aapache%3Acordova%3A2"
                }
            ],
            "vulnerabilities": [
                {
                    "source": "NVD",
                    "name": "CVE-2012-6637",
                    "severity": "HIGH",
                    "cvssv2": {
                        "score": 7.5,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "PARTIAL",
                        "severity": "HIGH",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "6.4"
                    },
                    "cwes": [
                        "CWE-20"
                    ],
                    "description": "Apache Cordova 3.3.0 and earlier and Adobe PhoneGap 2.9.0 and earlier do not anchor the end of domain-name regular expressions, which allows remote attackers to bypass a whitelist protection mechanism via a domain name that contains an acceptable name as an initial substring.",
                    "notes": "",
                    "references": [
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/seclists.org\/bugtraq\/2014\/Jan\/96",
                            "name": "20140124 Security Vulnerabilities in Apache Cordova \/ PhoneGap"
                        },
                        {
                            "source": "MLIST",
                            "url": "http:\/\/openwall.com\/lists\/oss-security\/2014\/02\/07\/9",
                            "name": "[oss-security] 20140207 Re: CVE request: multiple issues in Apache Cordova\/PhoneGap"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3",
                            "name": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf",
                            "name": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/labs.mwrinfosecurity.com\/blog\/2012\/04\/30\/building-android-javajavascript-bridges\/",
                            "name": "http:\/\/labs.mwrinfosecurity.com\/blog\/2012\/04\/30\/building-android-javajavascript-bridges\/"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt",
                            "name": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "2.9.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.1:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.9.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:*:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.3.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.3.0:rc1:*:*:*:*:*:*"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2014-1881",
                    "severity": "HIGH",
                    "cvssv2": {
                        "score": 7.5,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "PARTIAL",
                        "severity": "HIGH",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "6.4"
                    },
                    "cwes": [
                        "CWE-264"
                    ],
                    "description": "Apache Cordova 3.3.0 and earlier and Adobe PhoneGap 2.9.0 and earlier allow remote attackers to bypass intended device-resource restrictions of an event-based bridge via a crafted library clone that leverages IFRAME script execution and waits a certain amount of time for an OnJsPrompt handler return value as an alternative to correct synchronization.",
                    "notes": "",
                    "references": [
                        {
                            "source": "MLIST",
                            "url": "http:\/\/openwall.com\/lists\/oss-security\/2014\/02\/07\/9",
                            "name": "[oss-security] 20140207 Re: CVE request: multiple issues in Apache Cordova\/PhoneGap"
                        },
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/seclists.org\/bugtraq\/2014\/Jan\/96",
                            "name": "20140124 Security Vulnerabilities in Apache Cordova \/ PhoneGap"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3",
                            "name": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf",
                            "name": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt",
                            "name": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "2.9.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.1:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.9.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:*:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.3.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.3.0:rc1:*:*:*:*:*:*"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2014-1882",
                    "severity": "HIGH",
                    "cvssv2": {
                        "score": 7.5,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "PARTIAL",
                        "severity": "HIGH",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "6.4"
                    },
                    "cwes": [
                        "CWE-264"
                    ],
                    "description": "Apache Cordova 3.3.0 and earlier and Adobe PhoneGap 2.9.0 and earlier allow remote attackers to bypass intended device-resource restrictions of an event-based bridge via a crafted library clone that leverages IFRAME script execution and directly accesses bridge JavaScript objects, as demonstrated by certain cordova.require calls.",
                    "notes": "",
                    "references": [
                        {
                            "source": "MLIST",
                            "url": "http:\/\/openwall.com\/lists\/oss-security\/2014\/02\/07\/9",
                            "name": "[oss-security] 20140207 Re: CVE request: multiple issues in Apache Cordova\/PhoneGap"
                        },
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/seclists.org\/bugtraq\/2014\/Jan\/96",
                            "name": "20140124 Security Vulnerabilities in Apache Cordova \/ PhoneGap"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3",
                            "name": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf",
                            "name": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt",
                            "name": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "2.9.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.1:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.9.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:*:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.3.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.3.0:rc1:*:*:*:*:*:*"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2014-1884",
                    "severity": "HIGH",
                    "cvssv2": {
                        "score": 7.5,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "PARTIAL",
                        "severity": "HIGH",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "6.4"
                    },
                    "cwes": [
                        "CWE-264"
                    ],
                    "description": "Apache Cordova 3.3.0 and earlier and Adobe PhoneGap 2.9.0 and earlier on Windows Phone 7 and 8 do not properly restrict navigation events, which allows remote attackers to bypass intended device-resource restrictions via content that is accessed (1) in an IFRAME element or (2) with the XMLHttpRequest method by a crafted application.",
                    "notes": "",
                    "references": [
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/seclists.org\/bugtraq\/2014\/Jan\/96",
                            "name": "20140124 Security Vulnerabilities in Apache Cordova \/ PhoneGap"
                        },
                        {
                            "source": "MLIST",
                            "url": "http:\/\/openwall.com\/lists\/oss-security\/2014\/02\/07\/9",
                            "name": "[oss-security] 20140207 Re: CVE request: multiple issues in Apache Cordova\/PhoneGap"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3",
                            "name": "http:\/\/www.internetsociety.org\/ndss2014\/programme#session3"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf",
                            "name": "http:\/\/www.cs.utexas.edu\/~shmat\/shmat_ndss14nofrak.pdf"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt",
                            "name": "http:\/\/packetstormsecurity.com\/files\/124954\/apachecordovaphonegap-bypass.txt"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "2.9.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.2.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.3.0:rc2:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.4.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.5.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.6.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.7.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.8.1:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:adobe:phonegap:2.9.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:*:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.3.0"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.0.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.1.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:*:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.2.0:rc1:*:*:*:*:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:3.3.0:rc1:*:*:*:*:*:*"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2016-6799",
                    "severity": "HIGH",
                    "cvssv2": {
                        "score": 5.0,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "NONE",
                        "availabilityImpact": "NONE",
                        "severity": "MEDIUM",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "2.9",
                        "acInsufInfo": "true"
                    },
                    "cvssv3": {
                        "baseScore": 7.5,
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "NONE",
                        "availabilityImpact": "NONE",
                        "baseSeverity": "HIGH",
                        "exploitabilityScore": "3.9",
                        "impactScore": "3.6",
                        "version": "3.0"
                    },
                    "cwes": [
                        "CWE-532"
                    ],
                    "description": "Product: Apache Cordova Android 5.2.2 and earlier. The application calls methods of the Log class. Messages passed to these methods (Log.v(), Log.d(), Log.i(), Log.w(), and Log.e()) are stored in a series of circular buffers on the device. By default, a maximum of four 16 KB rotated logs are kept in addition to the current log. The logged data can be read using Logcat on the device. When using platforms prior to Android 4.1 (Jelly Bean), the log data is not sandboxed per application; any application installed on the device has the capability to read data logged by other applications.",
                    "notes": "",
                    "references": [
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/98365",
                            "name": "98365"
                        },
                        {
                            "source": "MLIST",
                            "url": "https:\/\/lists.apache.org\/thread.html\/1f3e7b0319d64b455f73616f572acee36fbca31f87f5b2e509c45b69@%3Cdev.cordova.apache.org%3E",
                            "name": "[dev] 20170509 CVE-2016-6799: Internal system information leak"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:android:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "5.2.2"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2017-3160",
                    "severity": "HIGH",
                    "cvssv2": {
                        "score": 5.8,
                        "accessVector": "NETWORK",
                        "accessComplexity": "MEDIUM",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "NONE",
                        "severity": "MEDIUM",
                        "version": "2.0",
                        "exploitabilityScore": "8.6",
                        "impactScore": "4.9"
                    },
                    "cvssv3": {
                        "baseScore": 7.4,
                        "attackVector": "NETWORK",
                        "attackComplexity": "HIGH",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "NONE",
                        "baseSeverity": "HIGH",
                        "exploitabilityScore": "2.2",
                        "impactScore": "5.2",
                        "version": "3.0"
                    },
                    "cwes": [
                        "NVD-CWE-noinfo"
                    ],
                    "description": "After the Android platform is added to Cordova the first time, or after a project is created using the build scripts, the scripts will fetch Gradle on the first build. However, since the default URI is not using https, it is vulnerable to a MiTM and the Gradle executable is not safe. The severity of this issue is high due to the fact that the build scripts immediately start a build after Gradle has been fetched. Developers who are concerned about this issue should install version 6.1.2 or higher of Cordova-Android. If developers are unable to install the latest version, this vulnerability can easily be mitigated by setting the CORDOVA_ANDROID_GRADLE_DISTRIBUTION_URL environment variable to https:\/\/services.gradle.org\/distributions\/gradle-2.14.1-all.zip",
                    "notes": "",
                    "references": [
                        {
                            "source": "MISC",
                            "url": "https:\/\/cordova.apache.org\/announcements\/2017\/01\/27\/android-612.html",
                            "name": "https:\/\/cordova.apache.org\/announcements\/2017\/01\/27\/android-612.html"
                        },
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/95838",
                            "name": "95838"
                        },
                        {
                            "source": "N\/A",
                            "url": "https:\/\/www.oracle.com\/security-alerts\/cpuapr2020.html",
                            "name": "N\/A"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:android:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndExcluding": "6.1.2"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2014-3500",
                    "severity": "MEDIUM",
                    "cvssv2": {
                        "score": 6.4,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "NONE",
                        "severity": "MEDIUM",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "4.9"
                    },
                    "cwes": [
                        "CWE-17"
                    ],
                    "description": "Apache Cordova Android before 3.5.1 allows remote attackers to change the start page via a crafted intent URL.",
                    "notes": "",
                    "references": [
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/69038",
                            "name": "69038"
                        },
                        {
                            "source": "CONFIRM",
                            "url": "http:\/\/cordova.apache.org\/announcements\/2014\/08\/04\/android-351.html",
                            "name": "http:\/\/cordova.apache.org\/announcements\/2014\/08\/04\/android-351.html"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:android:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.5.0"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2015-1835",
                    "severity": "MEDIUM",
                    "cvssv2": {
                        "score": 2.6,
                        "accessVector": "NETWORK",
                        "accessComplexity": "HIGH",
                        "authenticationr": "NONE",
                        "confidentialImpact": "NONE",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "NONE",
                        "severity": "LOW",
                        "version": "2.0",
                        "exploitabilityScore": "4.9",
                        "impactScore": "2.9",
                        "userInteractionRequired": "true"
                    },
                    "cvssv3": {
                        "baseScore": 5.3,
                        "attackVector": "NETWORK",
                        "attackComplexity": "HIGH",
                        "privilegesRequired": "NONE",
                        "userInteraction": "REQUIRED",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "NONE",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "NONE",
                        "baseSeverity": "MEDIUM",
                        "exploitabilityScore": "1.6",
                        "impactScore": "3.6",
                        "version": "3.0"
                    },
                    "cwes": [
                        "CWE-20"
                    ],
                    "description": "Apache Cordova Android before 3.7.2 and 4.x before 4.0.2, when an application does not set explicit values in config.xml, allows remote attackers to modify undefined secondary configuration variables (preferences) via a crafted intent: URL.",
                    "notes": "",
                    "references": [
                        {
                            "source": "MISC",
                            "url": "http:\/\/blog.trendmicro.com\/trendlabs-security-intelligence\/trend-micro-discovers-apache-vulnerability-that-allows-one-click-modification-of-android-apps\/",
                            "name": "http:\/\/blog.trendmicro.com\/trendlabs-security-intelligence\/trend-micro-discovers-apache-vulnerability-that-allows-one-click-modification-of-android-apps\/"
                        },
                        {
                            "source": "CONFIRM",
                            "url": "https:\/\/cordova.apache.org\/announcements\/2015\/05\/26\/android-402.html",
                            "name": "https:\/\/cordova.apache.org\/announcements\/2015\/05\/26\/android-402.html"
                        },
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/74866",
                            "name": "74866"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:android:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.7.1"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:4.0.0:*:*:*:*:android:*:*"
                            }
                        },
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:4.0.1:*:*:*:*:android:*:*"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2015-5207",
                    "severity": "MEDIUM",
                    "cvssv2": {
                        "score": 7.5,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "PARTIAL",
                        "severity": "HIGH",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "6.4"
                    },
                    "cvssv3": {
                        "baseScore": 5.3,
                        "attackVector": "LOCAL",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "REQUIRED",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "LOW",
                        "integrityImpact": "LOW",
                        "availabilityImpact": "LOW",
                        "baseSeverity": "MEDIUM",
                        "exploitabilityScore": "1.8",
                        "impactScore": "3.4",
                        "version": "3.0"
                    },
                    "cwes": [
                        "CWE-284",
                        "CWE-254"
                    ],
                    "description": "Apache Cordova iOS before 4.0.0 might allow attackers to bypass a URL whitelist protection mechanism in an app and load arbitrary resources by leveraging unspecified methods.",
                    "notes": "",
                    "references": [
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/88764",
                            "name": "88764"
                        },
                        {
                            "source": "JVNDB",
                            "url": "http:\/\/jvndb.jvn.jp\/en\/contents\/2016\/JVNDB-2016-000058.html",
                            "name": "JVNDB-2016-000058"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/136840\/Apache-Cordova-iOS-3.9.1-Access-Bypass.html",
                            "name": "http:\/\/packetstormsecurity.com\/files\/136840\/Apache-Cordova-iOS-3.9.1-Access-Bypass.html"
                        },
                        {
                            "source": "JVN",
                            "url": "http:\/\/jvn.jp\/en\/jp\/JVN35341085\/index.html",
                            "name": "JVN#35341085"
                        },
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/www.securityfocus.com\/archive\/1\/538211\/100\/0\/threaded",
                            "name": "20160427 CVE-2015-5207 - Bypass of Access Restrictions in Apache Cordova iOS"
                        },
                        {
                            "source": "CONFIRM",
                            "url": "https:\/\/cordova.apache.org\/announcements\/2016\/04\/27\/security.html",
                            "name": "https:\/\/cordova.apache.org\/announcements\/2016\/04\/27\/security.html"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:iphone_os:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.9.1"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2015-8320",
                    "severity": "MEDIUM",
                    "cvssv2": {
                        "score": 5.0,
                        "accessVector": "NETWORK",
                        "accessComplexity": "LOW",
                        "authenticationr": "NONE",
                        "confidentialImpact": "PARTIAL",
                        "integrityImpact": "NONE",
                        "availabilityImpact": "NONE",
                        "severity": "MEDIUM",
                        "version": "2.0",
                        "exploitabilityScore": "10.0",
                        "impactScore": "2.9"
                    },
                    "cwes": [
                        "NVD-CWE-Other"
                    ],
                    "description": "Apache Cordova-Android before 3.7.0 improperly generates random values for BridgeSecret data, which makes it easier for attackers to conduct bridge hijacking attacks by predicting a value.",
                    "notes": "",
                    "references": [
                        {
                            "source": "CONFIRM",
                            "url": "https:\/\/cordova.apache.org\/announcements\/2015\/11\/20\/security.html",
                            "name": "https:\/\/cordova.apache.org\/announcements\/2015\/11\/20\/security.html"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/134496\/Apache-Cordova-Android-3.6.4-BridgeSecret-Weak-Randomization.html",
                            "name": "http:\/\/packetstormsecurity.com\/files\/134496\/Apache-Cordova-Android-3.6.4-BridgeSecret-Weak-Randomization.html"
                        },
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/www.securityfocus.com\/archive\/1\/536945\/100\/0\/threaded",
                            "name": "20151120 Fwd: CVE-2015-5257 - Weak Randomization of BridgeSecret for Apache Cordova Android"
                        },
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/77679",
                            "name": "77679"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:android:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.6.4"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2015-5208",
                    "severity": "MEDIUM",
                    "cvssv2": {
                        "score": 4.3,
                        "accessVector": "NETWORK",
                        "accessComplexity": "MEDIUM",
                        "authenticationr": "NONE",
                        "confidentialImpact": "NONE",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "NONE",
                        "severity": "MEDIUM",
                        "version": "2.0",
                        "exploitabilityScore": "8.6",
                        "impactScore": "2.9",
                        "userInteractionRequired": "true"
                    },
                    "cvssv3": {
                        "baseScore": 4.4,
                        "attackVector": "LOCAL",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "REQUIRED",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "LOW",
                        "integrityImpact": "LOW",
                        "availabilityImpact": "NONE",
                        "baseSeverity": "MEDIUM",
                        "exploitabilityScore": "1.8",
                        "impactScore": "2.5",
                        "version": "3.0"
                    },
                    "cwes": [
                        "CWE-20"
                    ],
                    "description": "Apache Cordova iOS before 4.0.0 allows remote attackers to execute arbitrary plugins via a link.",
                    "notes": "",
                    "references": [
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/136839\/Apache-Cordova-iOS-3.9.1-Arbitrary-Plugin-Execution.html",
                            "name": "http:\/\/packetstormsecurity.com\/files\/136839\/Apache-Cordova-iOS-3.9.1-Arbitrary-Plugin-Execution.html"
                        },
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/88797",
                            "name": "88797"
                        },
                        {
                            "source": "JVN",
                            "url": "http:\/\/jvn.jp\/en\/jp\/JVN41772178\/index.html",
                            "name": "JVN#41772178"
                        },
                        {
                            "source": "JVNDB",
                            "url": "http:\/\/jvndb.jvn.jp\/en\/contents\/2016\/JVNDB-2016-000059.html",
                            "name": "JVNDB-2016-000059"
                        },
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/www.securityfocus.com\/archive\/1\/538210\/100\/0\/threaded",
                            "name": "20160427 CVE-2015-5208 - Arbitrary plugin execution issue in Apache Cordova iOS"
                        },
                        {
                            "source": "CONFIRM",
                            "url": "https:\/\/cordova.apache.org\/announcements\/2016\/04\/27\/security.html",
                            "name": "https:\/\/cordova.apache.org\/announcements\/2016\/04\/27\/security.html"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:iphone_os:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.9.1"
                            }
                        }
                    ]
                },
                {
                    "source": "NVD",
                    "name": "CVE-2015-5256",
                    "severity": "MEDIUM",
                    "cvssv2": {
                        "score": 4.3,
                        "accessVector": "NETWORK",
                        "accessComplexity": "MEDIUM",
                        "authenticationr": "NONE",
                        "confidentialImpact": "NONE",
                        "integrityImpact": "PARTIAL",
                        "availabilityImpact": "NONE",
                        "severity": "MEDIUM",
                        "version": "2.0",
                        "exploitabilityScore": "8.6",
                        "impactScore": "2.9",
                        "userInteractionRequired": "true"
                    },
                    "cwes": [
                        "CWE-264"
                    ],
                    "description": "Apache Cordova-Android before 4.1.0, when an application relies on a remote server, improperly implements a JavaScript whitelist protection mechanism, which allows attackers to bypass intended access restrictions via a crafted URI.",
                    "notes": "",
                    "references": [
                        {
                            "source": "BID",
                            "url": "http:\/\/www.securityfocus.com\/bid\/77677",
                            "name": "77677"
                        },
                        {
                            "source": "CONFIRM",
                            "url": "https:\/\/cordova.apache.org\/announcements\/2015\/11\/20\/security.html",
                            "name": "https:\/\/cordova.apache.org\/announcements\/2015\/11\/20\/security.html"
                        },
                        {
                            "source": "MISC",
                            "url": "http:\/\/packetstormsecurity.com\/files\/134497\/Apache-Cordova-3.7.2-Whitelist-Failure.html",
                            "name": "http:\/\/packetstormsecurity.com\/files\/134497\/Apache-Cordova-3.7.2-Whitelist-Failure.html"
                        },
                        {
                            "source": "BUGTRAQ",
                            "url": "http:\/\/www.securityfocus.com\/archive\/1\/536944\/100\/0\/threaded",
                            "name": "20151120 Fwd: CVE-2015-5256: Apache Cordova vulnerable to improper application of whitelist restrictions"
                        },
                        {
                            "source": "JVNDB",
                            "url": "http:\/\/jvndb.jvn.jp\/en\/contents\/2015\/JVNDB-2015-000187.html",
                            "name": "JVNDB-2015-000187"
                        },
                        {
                            "source": "JVN",
                            "url": "http:\/\/jvn.jp\/en\/jp\/JVN18889193\/index.html",
                            "name": "JVN#18889193"
                        }
                    ],
                    "vulnerableSoftware": [
                        {
                            "software": {
                                "id": "cpe:2.3:a:apache:cordova:*:*:*:*:*:android:*:*",
                                "vulnerabilityIdMatched": "true",
                                "versionEndIncluding": "3.6.4"
                            }
                        }
                    ]
                }
            ]
        }
    ]
}

    """

    # load the file; the format of the folder is dependencycheck_output/apk_name/dependency-check-report.json

    apk_name = _output[:-4]

    f = open('dependencycheck_output/' + apk_name + '/dependency-check-report.json')

    data = json.load(f)

    try:
        print(data['dependencies'][2]['vulnerabilities'])

        print('\n\n\n\n\ ================================================================= \n\n\n')
    except IndexError:
        # print('No dependencies found')
        # return
        pass

if __name__ == "__main__":

    # List all the apk files form current working directory.
    apk_files = [f for f in os.listdir("apps/") if f.endswith(".apk")]

    # j = 0
    # for i, apk_name in enumerate(apk_files):
        # apkid_parsed = parse_apkid_output(apk_name)
        # apkleaks_parsed = parse_apkleaks_output(apk_name)
        # flowdroid_parsed = parse_flowdroid_output(apk_name)
        # parse_dependencycheck_output(apk_name)
        # mobsf_parsed = parse_mobsf_output(apk_name)

    # Create output folders, if they don't exist.
    # create_output_folders()

    start_time = time.time()

    # # Run the tools on all the apk files.
    for apk in apk_files:

    #     # Run apkid
    #     run_apkid(apk)

    #     # Run apkleaks
    #     run_apkleaks(apk)

    #     # Run dex2jar and dependency-check
        run_d_check(apk)

    #     # Run mobsf
    #     run_mobsf(apk)

    #     # Run flowdroid
    #     run_flowdroid(apk)

    print("--- %s seconds ---" % (time.time() - start_time))
