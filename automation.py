import os
import subprocess
from mobsftester import *
import time
import xmltodict
import json
import matplotlib.pyplot as plt
import numpy as np

# pylint: disable=pointless-string-statement
"""
    Program that primarily handles running the following tools, saving outputs in a subsequent folder:

    1. apkid
    2. apkleaks
    3. mobsf
    4. flowdroid

    The program also handles the following:
        - parsing outputs for all of the aformentioned tools
        - creating a visual representation of the distribution of running times for each tool
        - creating a visual representation of possible correlations between number of findings and apk / dex sizes.
'"""

def run_apkid(_name):
    """
    Runs apkid on the apk file.

    Args:
        _name (str): The name of the apk file

    Returns:
        - The raw output of apkid in txt format, or add a new line to the timeouts.txt file, should the tool timeout while running.
    """
    print(f"Running apkid on apps/{_name}")

    start_time = time.time()

    # apkid command construction
    apkid_cmd = f"apkid -v apps/{_name} > apkid_output/{_name[:-4]}_apkid.txt"

    try:

        # Run apkid
        subprocess.run(apkid_cmd, shell = True, timeout = 60, check = True)
        
        end_time = "{:.2f}".format(float(time.time() - start_time))

        # write the amount of time it took to run apkid
        with open("runtimes/runtime_apkid.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

    # apkid timed out -> add it to the timeouts.txt file
    except subprocess.TimeoutExpired:
        
        # Add a new line to the timeouts.txt file
        with open("timeouts.txt", "a") as f:
            f.write(f"apkid: {_name}\n")

        print("TIMEOUT + apkid timed out + TIMEOUT on the following app: " + _name)
        return

def run_apkleaks(_name):
    """
    Runs apkleaks on the apk file.

    Args:
        _name (str): The name of the apk file

    Returns:
        - The raw output of apkleaks in txt format, or add a new line to the timeouts.txt file, should the tool timeout while running.
    """
    print(f"Running apkleaks on apps/{_name}")

    start_time = time.time()

    # apkleaks command construction
    apkleaks_cmd = f"apkleaks -f apps/{_name} -o apkleaks_output/{_name[:-4]}_apkleaks.txt"

    try:

        # Run apkleaks
        subprocess.run(apkleaks_cmd, shell = True, timeout = 150, check = True)

        end_time = "{:.2f}".format(float(time.time() - start_time))
        
        # write the amount of time it took to run apkleaks
        with open("runtimes/runtime_apkleaks.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

    # apkleaks timed out -> add it to the timeouts.txt file
    except subprocess.TimeoutExpired:

        # Add a new line to the timeouts.txt file
        with open("timeouts.txt", "a") as f:
            f.write(f"apkleaks: {_name}\n")

        print("TIMEOUT + apkleaks timed out + TIMEOUT on the following app: " + _name)
        return

def run_flowdroid(_name):
    """
    Runs flowdroid on the apk file.
        
    Args:
        _name (str): The name of the apk file

    Returns:
        - May return either the xml result of running flowdroid or add a new line to the timeouts.txt file, should the tool timeout while running.
    """
    print(f"Running flowdroid on {_name}")

    # TODO make this a .env file
    # also the SDK from the command
    flow_droid_folder = "/Users/vlad/Desktop/THESIS/FlowDroid-2.10"

    start_time = time.time()

    # flowdroid command construction
    flowdroid_cmd = f"java -jar {flow_droid_folder}/soot-infoflow-cmd/target/soot-infoflow-cmd-jar-with-dependencies.jar -s {flow_droid_folder}/soot-infoflow-android/SourcesAndSinks.txt -a apps/{_name} -p /Users/vlad/Library/Android/sdk/platforms -o flowdroid_output/{_name[:-4]}_flowdroid.xml"

    try:
        # Run flowdroid
        subprocess.run(flowdroid_cmd, shell = True, timeout = 150, check = True)

        end_time = "{:.2f}".format(float(time.time() - start_time))

        # write the amount of time it took to run flowdroid
        with open("runtimes/runtime_flowdroid.txt", "a") as runtime_file:
            runtime_file.write(f"{_name}: {end_time}\n")

    # flowdroid timed out -> add it to the timeouts.txt file
    except subprocess.TimeoutExpired:
        
        # Add a new line to the timeouts.txt file
        with open("flowdroid_timeouts.txt", "a") as f:
            f.write(f"flowdroid: {_name}\n")

        print("TIMEOUT + flowdroid timed out + TIMEOUT on the following app: " + _name)
        return
    

def run_mobsf(_name):
    """
    Runs mobsf on the apk file.

    Args:
        _name (str): The name of the apk file

    Returns:
        - The raw output of mobsf in json format.
    """
    start_time = time.time()

    # upload file to mobsf server
    RESP = upload(f"apps/{_name}")

    # send the scan command to the server
    scan(RESP)

    # get the output of the scan in json format
    response = json_resp(RESP)

    # save the response in a json file
    json.dump(response, open("mobsf_output/" + _name[:-4] + "_mobsf.json", "w"))

    end_time = "{:.2f}".format(float(time.time() - start_time))

    # write the amount of time it took to run mobsf
    with open("runtimes/runtime_mobsf.txt", "a") as runtime_file:
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
    Parses the output of apkid.

    Args:
        _output (str): The raw output of apkid as a txt file

    Returns:
        - The parsed output of apkid in json format.
    """
    result = {}

    # open the output file
    with open("apkid_output/" + _output[:-4] + "_apkid.txt", "r") as f:

        # read the file line by line
        for line in f:

            
            if "anti_vm" in line:
                # originally, the line looks like this:  |-> anti_vm : Build.FINGERPRINT check, Build.MANUFACTURER check
                # so we need to clean it up accordingly

                anti_vm = line.split("anti_vm : ")[1].strip() # removes extra symbols

                # transform Build.FINGERPRINT check, Build.MANUFACTURER check into array
                anti_vm = anti_vm.split(", ")

                result["anti_vm"] = anti_vm

            if "compiler" in line:
                # similarly to the "anti_vm" we have to clean the line

                compiler = line.split("compiler : ")[1].strip()

                result["compiler"] = compiler

    return result

def parse_apkleaks_output(_output):
    """
    Parses the output of apkleaks.

    Args:
        _output (str): The raw output of apkleaks as a txt file

    Returns:
        - The parsed output of apkleaks in json format.
    """
    result = {}

    try:
        with open("apkleaks_output/" + _output[:-4] + "_apkleaks.txt", "r") as f:
            finding = ""

            # read the file line by line
            for i, line in enumerate(f):
                # It's important to note that the lines look like this:
                # 
                # [IP_Address]
                # - 19.3.1.1
                # - 35.1.1.1
                # [LinkFinder]
                # - activity_choser_model_history.xml
                # ...

                # if the line contains `[name_of_finding]`, then we know we found a new type of finding
                # eg within [IP_Address] until [LinkFinder] is found
                if line[0] == "[":
                    finding = line.strip("[]\n")
                    result[finding] = []
                else:
                    # otherwise, we are inside a finding, we will keep appending each line that starts with `-` to it
                    if finding:
                        line = line.strip("- \n")
                        if len(line) > 0:
                            result[finding].append(line)
    except FileNotFoundError:
        print("File not found")
    return result

def parse_flowdroid_output(_output):
    """
    Parses the output of flowdroid.

    Args:
        _output (str): The raw output of flowdroid as a xml file

    Returns:
        - The parsed output of flowdroid in json format.
    """

    # we try to use the xmltodict library;
    try:
        with open("flowdroid_output/" + _output[:-4] + "_flowdroid.xml", "rb") as f:
            
            # pars the file
            parsed_file = xmltodict.parse(f)

            # After the file is parsed, it looks like the flowdroid_test.json file
            return parsed_file

    # if xmltodict fails, that means the particular file has timeouted.
    except FileNotFoundError:
        pass

def parse_mobsf_output(_output):
    """
    Parses the output of mobsf.

    Args:
        _output (str): The raw output of mobsf as json

    Returns:
        - The parsed output of mobsf in json format, selecting the most relevant fields.
    """
    result = {}

    output_file = open("mobsf_output/" + _output[:-4] + "_mobsf.json")
    response = json.load(output_file)

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

    Args:
        _name (str): The name of the apk file.

    Returns:
        - The size of the apk in MB.
    """
    app_mb = os.path.getsize("apps/" + _name) / 1024 / 1024
    
    return float("{:.2f}".format(app_mb))

def get_dex_size(_name):
    """
    Returns the sum of the sizes of dex files within an apk.

    Args:
        _name (str): The name of the apk file.

    Returns:
        - The sum of the sizes of dex files within an apk, in MB.
    """
    total_mb =  0

    # try this if the apk has not already been unpacked:
    if not os.path.exists(f"temp_apk/target_{_name[:-4]}"):
        os.system(f"unzip apps/{_name} -d temp_apk/target_{_name[:-4]}")
    
    # retrieve all the dex files from the target folder, recursivelly
    for root, dirs, files in os.walk(f"temp_apk/target_{_name[:-4]}"):
        for file in files:

            # if the file is a dex file, add its size to the total
            if file.endswith(".dex"):
                total_mb += os.path.getsize(os.path.join(root, file)) / 1024 / 1024

    return float("{:.2f}".format(total_mb))

def distribution_running_times(_tool_runtime):
    """
    Plots the distribution of running times for an app using the matplotlib library.

    Args:
        _tool_runtime (dict): The running times of a tool.

    Returns:
        - The distribution of running times for an app as a png histogram.
    """
    with open(f"runtimes/{_tool_runtime}", "r") as f:
        running_times = f.readlines()

    # the structure of the file looks like this:
    # app_name: runtime ; thus we only need the runtime
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
    plt.title("Distribution of Running Times for " + _tool_runtime.split("_")[1][:-4])
    plt.xlabel("Running Time (seconds)")
    plt.ylabel("Frequency")
    print(max(running_times))
    plt.xticks(np.arange(min(running_times), max(running_times), 10))
    plt.savefig(f'statistics/distribution_runtimes_{_tool_runtime.split("_")[1][:-4]}.png')

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
    
    # depending on the selected tool, there's different ways to count the important findings
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
        nr_findings += len(parsed_mobsf["permissions"])

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

    Returns:
        The correlation of the number of findings to the size of the apk or dex files, as a png scatter plot.
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
    plt.savefig(f"statistics/correlation_{_option}_size_nrfindings_{_tool}.png")

    # calculate Pearson correlation coefficient
    # pearson_corr = np.corrcoef(size_array, nr_findings)
    # print("Pearson correlation coefficient: ", pearson_corr)

def summarise_results():
    """
    Summarises the results, aggregating the highest severity findings of all results.

    Returns:
        A dictionary containing the highest severity findings of all results.
    """
    # get the highest severity findings of all results
    highest_severity_findings = {"apkid": [], "mobsf": [], "apkleaks": [], "flowdroid": []}
    apk_files = [f for f in os.listdir("apps/") if f.endswith(".apk")]

    for apk_name in apk_files:
        
        # select highest severity findings of the parsed apkid results
        apkid_parsed = parse_apkid_output(apk_name)

        for key, value in apkid_parsed.items():

            # check if any of the following is within the value, then we can mark it as suspicious
            suspicious = ["axmlprinter2", "apktool", "suspicious", "link", "obfuscator", "dexlib", "smali", "apktool"]

            for suspicious_string in suspicious:
                if suspicious_string in value:
                    highest_severity_findings["apkid"].append(
                        (apk_name, key) # add the key instead, for cleaner summary; up to the reasearcher to look into the specific output file
                    )

        # select highest severity findings of the parsed apkleaks results
        apkleaks_parsed = parse_apkleaks_output(apk_name)

        for key, value in apkleaks_parsed.items():

            # check the regexes here https://github.com/dwisiswant0/apkleaks/blob/master/config/regexes.json
            # essentially, the most severe results here can be secret keys and/ or API keys
            # if "Key" in key or "Token" in key:
            suspicious = ["Key", "Token", "OAuth"]
            for suspicious_string in suspicious:
                if suspicious_string in key:
                    highest_severity_findings["apkleaks"].append(
                        (apk_name, key) # add the key instead, for cleaner summary; up to the reasearcher to look into the specific output file
                    )

        # select highest severity findings of the parsed flowdroid results
        flowdroid_parsed = parse_flowdroid_output(apk_name)
        # print(flowdroid_parsed)

        if flowdroid_parsed:
            # print("YES")
            # print(flowdroid_parsed.keys())
            if "Results" in flowdroid_parsed['DataFlowResults']:
                highest_severity_findings["flowdroid"].append(
                    (apk_name, len(flowdroid_parsed['DataFlowResults']['Results']['Result'])) # append nr of results
                )

        # select highest severity findings of the parsed mobsf results
        mobsf_parsed = parse_mobsf_output(apk_name)
        
        if mobsf_parsed["trackers"]["detected_trackers"]:
            highest_severity_findings["mobsf"].append((apk_name, "trackers"))
 
        if mobsf_parsed["secrets"]:
            highest_severity_findings["mobsf"].append((apk_name, "secrets"))

        if mobsf_parsed["appsec"]["high"]:
            highest_severity_findings["mobsf"].append((apk_name, "appsec"))
    
    # sort the array based on nr of findings (apk_name, nr_findings)
    highest_severity_findings["flowdroid"] = sorted(highest_severity_findings["flowdroid"], key=lambda x: x[1], reverse=True)

    return highest_severity_findings

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

    final_res = {}

    start_time = time.time()

    # Create output folders, if they don't exist.
    create_output_folders()
            
    # Run the tools.
    # run_tools(apk_files)

    # Print total running time of the automation procedure.
    # final_time = "{:.2f}".format(float(time.time() - start_time))
    # print(f"--- {final_time} seconds --- ")

    # Statistics: 
    # NOTE Don't run all of them at the same time, the matplotlib library is not thread safe.
    # (https://stackoverflow.com/questions/41903300/matplotlib-crashes-when-running-in-parallel)
    # Essentially, it yields memory corrupted plots; run each function at a time.

    # Correlation of the number of findings to the size of the dex files.
    # correlation_size_nrfindings(apk_files, "apkid", "dex")
    # correlation_size_nrfindings(apk_files, "apkleaks", "dex")
    # correlation_size_nrfindings(apk_files, "mobsf", "dex")
    # correlation_size_nrfindings(apk_files, "flowdroid", "dex")

    # Correlation of the number of findings to the size of the apk files.
    # correlation_size_nrfindings(apk_files, "apkid", "apk")
    # correlation_size_nrfindings(apk_files, "apkleaks", "apk")
    # correlation_size_nrfindings(apk_files, "mobsf", "apk")
    # correlation_size_nrfindings(apk_files, "flowdroid", "apk")

    # Distribution of the number of findings.
    # distribution_running_times("runtime_flowdroid.txt")
    # distribution_running_times("runtime_apkid.txt")
    # distribution_running_times("runtime_apkleaks.txt")
    # distribution_running_times("runtime_mobsf.txt")

    # Summarise the results
    # final_res = summarise_results()