import os
import sys
import subprocess
from mobsftester import *
import time
import xmltodict

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
        d_check_cmd_json = f"dependency-check -n -s temp_jar/{_name[:-4]}.jar -f JSON -o dependencycheck_output/{_name[:-4]}"
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



if __name__ == "__main__":

    # List all the apk files form current working directory.
    apk_files = [f for f in os.listdir("apps/") if f.endswith(".apk")]

    j = 0
    for i, apk_name in enumerate(apk_files):
        # apkid_parsed = parse_apkid_output(apk_name)
        # apkleaks_parsed = parse_apkleaks_output(apk_name)
        # flowdroid_parsed = parse_flowdroid_output(apk_name)
        # dcheck_parsed = parse_dependencycheck_output(apk_name)
        # mobsf_parsed = parse_mobsf_output(apk_name)

    # Create output folders, if they don't exist.
    # create_output_folders()

    # start_time = time.time()

    # # Run the tools on all the apk files.
    # for apk in apk_files:

    #     # Run apkid
    #     run_apkid(apk)

    #     # Run apkleaks
    #     run_apkleaks(apk)

    #     # Run dex2jar and dependency-check
    #     run_d_check(apk)

    #     # Run mobsf
    #     run_mobsf(apk)

    #     # Run flowdroid
    #     run_flowdroid(apk)

    # print("--- %s seconds ---" % (time.time() - start_time))