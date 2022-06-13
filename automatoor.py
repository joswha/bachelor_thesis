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

    start_time = time.time()

    # Run apkid
    # apkid_cmd = f"apkid -v apps/{_name} > apkid_output/{_name[:-4]}_apkid.txt"
    apkid_cmd = f"apkid -v apps/{_name}"

    try:
        subprocess.run(apkid_cmd, shell = True, timeout = 60, check = True)
        
        end_time = "{:.2f}".format(float(time.time() - start_time))

        with open("runtime_apkid.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

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

    start_time = time.time()

    # Run apkleaks
    # apkleaks_cmd = f"apkleaks -f apps/{_name} -o apkleaks_output/{_name[:-4]}_apkleaks.txt"
    apkleaks_cmd = f"apkleaks -f apps/{_name}"

    try:
        subprocess.run(apkleaks_cmd, shell = True, timeout = 150, check = True)

        end_time = "{:.2f}".format(float(time.time() - start_time))

        with open("runtime_apkleaks.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

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

    start_time = time.time()

    try:
        # Run dex2jar
        d2j_cmd = f"d2j-dex2jar apps/{_name} -o temp_jar/{_name[:-4]}.jar"
        subprocess.run(d2j_cmd, shell = True, timeout = 20, check = True)

        # Run dependency-check
        d_check_cmd_json = f"dependency-check -s temp_jar/{_name[:-4]}.jar -f JSON -o dependencycheck_output/{_name[:-4]}"
        # had to add -n so that no update is done, this got me a lot of errors
        subprocess.run(d_check_cmd_json, shell = True, timeout = 40, check = True)

        end_time = "{:.2f}".format(float(time.time() - start_time))

        with open("runtime_dcheck.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

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

    start_time = time.time()

    # Run flowdroid
    # flowdroid -a ../bachelor_thesis/apps/cam3.apk -p /Users/vlad/Library/Android/sdk/platforms -s soot-infoflow-android/SourcesAndSinks.txt
    flowdroid_cmd = f"java -jar {flow_droid_folder}/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar -s {flow_droid_folder}/soot-infoflow-android/SourcesAndSinks.txt -a apps/{_name} -p /Users/vlad/Library/Android/sdk/platforms -o flowdroid_output/{_name[:-4]}_flowdroid.xml"

    try:
        subprocess.run(flowdroid_cmd, shell = True, timeout = 150, check = True)

        end_time = "{:.2f}".format(float(time.time() - start_time))

        with open("runtime_flowdroid.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

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
    start_time = time.time()
    RESP = upload(f"apps/{_name}")
    scan(RESP)
    # json_resp(RESP)
    # pdf(RESP, _name[:-4])

    end_time = "{:.2f}".format(float(time.time() - start_time))

    with open("runtime_mobsf.txt", "a") as runtime_file:
        runtime_file.write(f"{_name}: {end_time}\n")

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
    result = {}

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
    result = {}

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
    The flowdroid output is in xml format and can look like this:

    <?xml version="1.0" encoding="UTF-8"?><DataFlowResults FileFormatVersion="102" TerminationState="Success"><Results><Result><Sink Statement="virtualinvoke $r5.&lt;java.io.OutputStream: void write(byte[],int,int)&gt;(r3, 0, $i1)" Method="&lt;protect.babymonitor.MonitorActivity: void serviceConnection(java.net.Socket)&gt;"><AccessPath Value="$i1" Type="int" TaintSubFields="true"></AccessPath></Sink><Sources><Source Statement="$i1 = virtualinvoke r2.&lt;android.media.AudioRecord: int read(byte[],int,int)&gt;(r3, 0, $i0)" Method="&lt;protect.babymonitor.MonitorActivity: void serviceConnection(java.net.Socket)&gt;"><AccessPath Value="$i1" Type="int" TaintSubFields="true"></AccessPath></Source></Sources></Result></Results><PerformanceData><PerformanceEntry Name="CallgraphConstructionSeconds" Value="1"></PerformanceEntry><PerformanceEntry Name="TotalRuntimeSeconds" Value="1"></PerformanceEntry><PerformanceEntry Name="MaxMemoryConsumption" Value="153"></PerformanceEntry><PerformanceEntry Name="SourceCount" Value="1"></PerformanceEntry><PerformanceEntry Name="SinkCount" Value="38"></PerformanceEntry></PerformanceData></DataFlowResults>     
    """
    try:
        with open("flowdroid_output/" + _output[:-4] + "_flowdroid.xml", "rb") as f:

            parsed_file = xmltodict.parse(f)

            # After the file is parsed, it looks like the flowdroid_test.json file
            return parsed_file

    except FileNotFoundError: # file not found if we have this as timeout.
        pass


def parse_dependencycheck_output(_output):
    """
    The output of the dependency checker is a JSON file, and it has the following format:

    Check the dcheck_test.json
    """

    # load the file; the format of the folder is dependencycheck_output/apk_name/dependency-check-report.json

    apk_name = _output[:-4]

    f = open('dependencycheck_output/' + apk_name + '/dependency-check-report.json', 'r')

    data = json.load(f)

    try:
        return data['dependencies'][0]['vulnerabilities']

    except KeyError:
        pass

def parse_mobsf_output(_output):
    """
    Parses the output of the MobSF tool.
    """
    result = {}
    RESP = upload(f"apps/{_output}")
    # return json_resp(RESP)
    response = json_resp(RESP)

    # Filter out important fields from the response.
    # permissions
    result["permissions"] = response["permissions"]
    # certificate_analysis
    result["certificate_analysis"] = response["certificate_analysis"]
    # manifest_analysis
    result["manifest_analysis"] = response["manifest_analysis"]
    # code_analysis
    result["code_analysis"] = response["code_analysis"]
    # niap_analysis
    result["niap_analysis"] = response["niap_analysis"]
    # urls
    result["urls"] = response["urls"]
    # domains
    result["domains"] = response["domains"]
    # emails
    result["emails"] = response["emails"]
    # strings
    result["strings"] = response["strings"]
    # firebase_urls
    result["firebase_urls"] = response["firebase_urls"]
    # files
    result["files"] = response["files"]
    # trackers
    result["trackers"] = response["trackers"]
    # secrets
    result["secrets"] = response["secrets"]
    # appsec
    result["appsec"] = response["appsec"]

    return result

if __name__ == "__main__":

    # List all the apk files form current working directory.
    apk_files = [f for f in os.listdir("apps/") if f.endswith(".apk")]

    final_res = {}

    start_time = time.time()

    # Parsing the outputs into a unified dictionary.
    # for i, apk_name in enumerate(apk_files):
        
    #     print("\n\n")
    #     print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
    #     print(f"Parsing: {i}'th {apk_name}")
    #     print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
    #     print("\n\n")

        # apkid_parsed = parse_apkid_output(apk_name)
        # apkleaks_parsed = parse_apkleaks_output(apk_name)
        # flowdroid_parsed = parse_flowdroid_output(apk_name)
        # dependencycheck_parsed = parse_dependencycheck_output(apk_name)
        # print(f"{apk_name}", dependencycheck_parsed)
        # mobsf_parsed = parse_mobsf_output(apk_name)

        # apk_res = {
        #     "apkid": apkid_parsed,
        #     "apkleaks": apkleaks_parsed,
        #     "flowdroid": flowdroid_parsed,
        #     "dependencycheck": dependencycheck_parsed,
        #     "mobsf": mobsf_parsed
        # }

    #     final_res[apk_name] = apk_res
        
    # print(final_res)

    # Create output folders, if they don't exist.
    # create_output_folders()


    # # Run the tools on all the apk files.
    for apk in apk_files:

    #     # Run apkid
        # run_apkid(apk)

    #     # Run apkleaks
        # run_apkleaks(apk)

    #     # Run dex2jar and dependency-check
        # run_d_check(apk)

    #     # Run mobsf
        run_mobsf(apk)

    #     # Run flowdroid
    #     run_flowdroid(apk)

    final_time = "{:.2f}".format(float(time.time() - start_time))
    print(f"--- {final_time} seconds --- ")
