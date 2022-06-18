import os
import sys
import subprocess
from mobsftester import *
import time
import xmltodict
import json
import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np

# pylint: disable=pointless-string-statement
"""
Program that handles running the following tools, saving outputs in a subsequent folder:

    1. apkid
    2. apkleaks
    3. mobsf
    4. flowdroid

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

def run_flowdroid(_name):
    """
    Runs flowdroid on the apk file.
    """
    print(f"Running flowdroid on {_name}")

    flow_droid_folder = "/Users/vlad/Desktop/THESIS/FlowDroid-2.10"

    start_time = time.time()

    # Run flowdroid
    # flowdroid -a ../bachelor_thesis/apps/cam3.apk -p /Users/vlad/Library/Android/sdk/platforms -s soot-infoflow-android/SourcesAndSinks.txt
    flowdroid_cmd = f"java -Xmx12g -jar {flow_droid_folder}/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar -s {flow_droid_folder}/soot-infoflow-android/SourcesAndSinks.txt -a apps/{_name} -p /Users/vlad/Library/Android/sdk/platforms -o 12gb/{_name[:-4]}_flowdroid.xml"

    try:
        subprocess.run(flowdroid_cmd, shell = True, timeout = 150, check = True)

        end_time = "{:.2f}".format(float(time.time() - start_time))

        with open("runtime_flowdroid.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

    except subprocess.TimeoutExpired:
        
        # Add a new line to the timeouts.txt file
        with open("timeouts_wrongers.txt", "a") as f:
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
    if not os.path.exists("temp_apk"):
        os.makedirs("temp_apk")

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
    # result["strings"] = response["strings"] # exclude, too long
    # firebase_urls
    result["firebase_urls"] = response["firebase_urls"]
    # files
    # result["files"] = response["files"]
    # trackers
    result["trackers"] = response["trackers"]
    # secrets
    result["secrets"] = response["secrets"]
    # appsec
    result["appsec"] = response["appsec"]

    return result

def get_apk_size(_name):
    """
    Returns the size of the apk in MB.
    """
    app_mb = os.path.getsize("apps/" + _name) / 1024 / 1024
    
    return float("{:.2f}".format(app_mb))

def get_dex_size(_name):
    """
    Returns the size of all dex files from an apk in MB.
    """
    total_mb =  0

    # try this if the apk has not already been unpacked:
    if not os.path.exists(f"temp_apk/target_{_name[:-4]}"):
        os.system(f"unzip apps/{_name} -d temp_apk/target_{_name[:-4]}")
    
    # retrieve all the dex files from the target folder, recursivelly
    for root, dirs, files in os.walk(f"temp_apk/target_{_name[:-4]}"):
        for file in files:
            if file.endswith(".dex"):
                total_mb += os.path.getsize(os.path.join(root, file)) / 1024 / 1024

    return float("{:.2f}".format(total_mb))

def distribution_running_times(_app_runtime):
    """
    Plots the distribution of running times for an app using the matplotlib library.
    """
    with open(_app_runtime, "r") as f:
        running_times = f.readlines()

    # the structure of the file looks like this:
    # app_name: runtime, we only need the runtime
    running_times = [float(x.split(":")[1].strip()) for x in running_times]

    running_times.sort()

    # exclude the outliers, calculated based on the quartile method
    q1 = np.percentile(running_times, 25)
    q3 = np.percentile(running_times, 75)
    iqr = q3 - q1
    lower_bound = q1 - (1.5 * iqr)
    upper_bound = q3 + (1.5 * iqr)

    # remove the outliers
    running_times = [x for x in running_times if lower_bound < x < upper_bound]
        
    # plot the distribution of running times for an app
    plt.hist(running_times, bins = 20, color = 'green', edgecolor = 'black')
    plt.title("Distribution of Running Times for " + _app_runtime.split("_")[1][:-4])
    plt.xlabel("Running Time (seconds)")
    plt.ylabel("Frequency")
    print(max(running_times))
    plt.xticks(np.arange(min(running_times), max(running_times), 10))
    plt.savefig(f'distribution_runtimes_{_app_runtime.split("_")[1][:-4]}.png')

def number_of_findings(_output, _tool):
    """
    Returns the number of findings in the output file.

    Args:
        _output: the output file of the tool.
        _tool: the tool that generated the output file.

    Returns:
        The number of relevant findings in the output file.
    """
    nr_findings = 0
    
    if _tool == "apkid":
        parsed_apkid = parse_apkid_output(_output)

        for key, value in parsed_apkid.items():        
            # check if value is an array
            if isinstance(value, list):
                nr_findings += len(value)
            else:
                nr_findings += 1

    elif _tool == "mobsf":
        parsed_mobsf = parse_mobsf_output(_output)

        nr_findings += (parsed_mobsf["trackers"]["detected_trackers"])
        nr_findings += len(parsed_mobsf["firebase_urls"])
        nr_findings += len(parsed_mobsf["secrets"])
        nr_findings += len(parsed_mobsf["emails"])
        nr_findings += len(parsed_mobsf["appsec"]["high"])
        nr_findings += len(parsed_mobsf["appsec"]["warning"])
        nr_findings += len(parsed_mobsf["appsec"]["info"])
        nr_findings += len(parsed_mobsf["appsec"]["hotspot"])

    elif _tool == "apkleaks":
        parse_apkleaks = parse_apkleaks_output(_output)

        for key in parse_apkleaks.keys():

            # This is an outlier having more than 6000 results in < 5 apks, compared to the average of ~30 results.
            # this only happens when selcting `dex` files, since ovrall they are much rather to include more results within the 
            # quartile selection method. 
            if key != "LinkFinder":
                nr_findings += len(parse_apkleaks[key])

    elif _tool == "flowdroid":

        parsed_flowdroid = parse_flowdroid_output(_output)

        if not parsed_flowdroid:
            return 0

        try:
            nr_findings += (len(parsed_flowdroid['DataFlowResults']['Results']['Result']))
            print(nr_findings)
        except KeyError:
            return

    else:
        print("Error: unknown tool")
        return

    return nr_findings

def correlation_size_nrfindings(_apk_files, _tool, _option):
    """
    Plots the correlation of the number of findings to the size of the apk or dex files.

    Args:
        _apk_files: list of apk files
        _tool: the tool used to generate the output file
        _option: apk or dex files that are being used
    """

    if _option == "apk":
        # get the size of apks
        size_dict = {f: get_apk_size(f) for f in os.listdir("apps/") if f.endswith(".apk")}
    elif _option == "dex":
        # get the size of dex files
        size_dict = {f: get_dex_size(f) for f in os.listdir("apps/") if f.endswith(".apk")}
    else:
        print("Invalid option")
        return

    # sort the size_dict based on the value and store it in a size array
    sorted_size_dict = sorted(size_dict.items(), key=lambda x: x[1])

    # exclude the outliers using the quartile method
    q1 = np.percentile([float(x[1]) for x in sorted_size_dict], 25)
    q3 = np.percentile([float(x[1]) for x in sorted_size_dict], 75)
    iqr = q3 - q1
    lower_bound = q1 - (1.5 * iqr)
    upper_bound = q3 + (1.5 * iqr)

    # remove the outliers
    sorted_size_dict = [x for x in sorted_size_dict if lower_bound < float(x[1]) < upper_bound]

    # transform into an array
    size_array = [float(y) for (x,y) in sorted_size_dict]

    nr_findings = [number_of_findings(x, _tool) for (x, y) in sorted_size_dict]

    # plot the correlation of the number of findings for each app
    plt.scatter(size_array, nr_findings, color = 'green', edgecolor = 'black')
    plt.title(f"Correlation size vs number of findings for {_tool}")
    plt.xlabel(f"{_option} Size (MB)")
    plt.ylabel("Number of Findings")
    plt.savefig(f"correlation_{_option}_size_nrfindings_{_tool}.png")

    # calculate Pearson correlation coefficient
    # pearson_corr = np.corrcoef(size_array, nr_findings)
    # print("Pearson correlation coefficient: ", pearson_corr)

def run_tools(_apk_files):
    """
    Run the tools on all the apk files.

    Returns:
        - Raw outputs from all of the tools organized by their subsequent output folders.
    """
    for apk in apk_files:

        # Run apkid
        run_apkid(apk)

        # Run apkleaks
        run_apkleaks(apk)

        # Run mobsf
        run_mobsf(apk)

        # Run flowdroid
        run_flowdroid(apk)

if __name__ == "__main__":

    # List all the apk files form current working directory.
    apk_files = [f for f in os.listdir("apps/") if f.endswith(".apk")]

    # Don't run all of them at the same time, the matplotlib library is not thread safe.(https://stackoverflow.com/questions/41903300/matplotlib-crashes-when-running-in-parallel)
    # Essentially, it yields memory corrupted plots; run each function at a time.

    # correlation_size_nrfindings(apk_files, "apkid", "dex")
    # correlation_size_nrfindings(apk_files, "apkleaks", "dex")
    # correlation_size_nrfindings(apk_files, "mobsf", "dex")
    # correlation_size_nrfindings(apk_files, "flowdroid", "dex")

    # correlation_size_nrfindings(apk_files, "apkid", "apk")
    # correlation_size_nrfindings(apk_files, "apkleaks", "apk")
    # correlation_size_nrfindings(apk_files, "mobsf", "apk")
    # correlation_size_nrfindings(apk_files, "flowdroid", "apk")

    # for run_time in ["apkid", "apkleaks", "mobsf", "flowdroid"]:
        # distribution_running_times(f"runtime_{run_time}.txt")
    distribution_running_times("runtime_flowdroid.txt")

    final_res = {}

    start_time = time.time()

    # Create output folders, if they don't exist.
    # create_output_folders()

    # apk_file = apk_files[23]
    # print(apk_file)
    # dex_size = get_dex_size(apk_file)
    # print(dex_size)

    # dex_sizes = []

    # for apk_file in apk_files:
    #     dex_sizes.append(get_dex_size(apk_file))

    
    # print(dex_sizes)


    # Parsing the outputs into a unified dictionary.
    # for i, apk_name in enumerate(apk_files):

        # size_dict[apk_name] = get_apk_size(apk_name)

        # apkid_parsed = parse_apkid_output(apk_name)
        # apkleaks_parsed = parse_apkleaks_output(apk_name)
        # flowdroid_parsed = parse_flowdroid_output(apk_name)

        # print(flowdroid_parsed)
        # j = 0
        # print(apk_name)

        # if flowdroid_parsed is not None:
            # print(f"{apk_name} is a wrong timeoutter")
            # print(f"{apk_name}: "+flowdroid_parsed['DataFlowResults']['PerformanceData']['PerformanceEntry'][3]['@Value']) # {'@Name': 'TotalRuntimeSeconds', '@Value': '84'}
                # print(flowdroid_parsed['DataFlowResults']['PerformanceData']['PerformanceEntry'][4])# {'@Name': 'MaxMemoryConsumption', '@Value': '2868'}

                
                # return
        # mobsf_parsed = parse_mobsf_output(apk_name)

        # apk_res = {
        #     "apkid": apkid_parsed,
        #     "apkleaks": apkleaks_parsed,
        #     "flowdroid": flowdroid_parsed,
        #     "mobsf": mobsf_parsed
        # }

    #     final_res[apk_name] = apk_res
        
    # print(final_res)
    
    # Run the tools.
    # run_tools(apk_tools)

    # distribution_running_times("runtime_flowdroid.txt")
    # distribution_running_times("runtime_apkid.txt")
    # distribution_running_times("runtime_apkleaks.txt")
    # distribution_running_times("runtime_flowdroid.txt")

    # distribution_size_nrfindings(apk_files, "flowdroid")
    # distribution_size_nrfindings(apk_files, "apkid")
    # distribution_size_nrfindings(apk_files, "mobsf")
    # distribution_size_nrfindings(apk_files, "apkleaks")

    # final_time = "{:.2f}".format(float(time.time() - start_time))
    # print(f"--- {final_time} seconds --- ")
