import os
import sys
import subprocess
from mobsftester import *
import time

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

if __name__ == "__main__":

    # List all the apk files form current working directory.
    # got to 38 after first run -> 37'th index
    # second time(internet dc -> apkleaks doesn't work) -> 55
    # apk_files = [f for f in os.listdir("apps/") if f.startswith("installer") and f.endswith(".apk")]
    apk_files = [f for f in os.listdir("apps/") if f.startswith("installer") and f.endswith(".apk")]

    timeouts_map = {'installer.apk', 'installer103.apk', 'installer104.apk', 'installer105.apk', 'installer106.apk', 'installer107.apk', 'installer109.apk', 'installer115.apk', 'installer121.apk', 'installer122.apk', 'installer126.apk', 'installer127.apk', 'installer130.apk', 'installer134.apk', 'installer136.apk', 'installer138.apk', 'installer142.apk', 'installer146.apk', 'installer152.apk', 'installer154.apk', 'installer157.apk', 'installer160.apk', 'installer164.apk', 'installer165.apk', 'installer168.apk', 'installer169.apk', 'installer17.apk', 'installer170.apk', 'installer173.apk', 'installer174.apk', 'installer175.apk', 'installer179.apk', 'installer182.apk', 'installer185.apk', 'installer186.apk', 'installer187.apk', 'installer189.apk', 'installer193.apk', 'installer205.apk', 'installer211.apk', 'installer212.apk', 'installer213.apk', 'installer215.apk', 'installer219.apk', 'installer224.apk', 'installer227.apk', 'installer23.apk', 'installer233.apk', 'installer234.apk', 'installer235.apk', 'installer238.apk', 'installer246.apk', 'installer250.apk', 'installer251.apk', 'installer252.apk', 'installer256.apk', 'installer257.apk', 'installer258.apk', 'installer261.apk', 'installer262.apk', 'installer267.apk', 'installer272.apk', 'installer274.apk', 'installer275.apk', 'installer277.apk', 'installer28.apk', 'installer281.apk', 'installer287.apk', 'installer295.apk', 'installer297.apk', 'installer3.apk', 'installer303.apk', 'installer304.apk', 'installer31.apk', 'installer310.apk', 'installer311.apk', 'installer312.apk', 'installer314.apk', 'installer320.apk', 'installer321.apk', 'installer327.apk', 'installer328.apk', 'installer329.apk', 'installer331.apk', 'installer334.apk', 'installer336.apk', 'installer339.apk', 'installer343.apk', 'installer347.apk', 'installer355.apk', 'installer361.apk', 'installer367.apk', 'installer371.apk', 'installer38.apk', 'installer380.apk', 'installer41.apk', 'installer46.apk', 'installer48.apk', 'installer55.apk', 'installer7.apk', 'installer71.apk', 'installer73.apk', 'installer76.apk', 'installer80.apk', 'installer83.apk', 'installer85.apk', 'installer97.apk', 'installer98.apk', 'installer3849.apk', 'installer3848.apk', 'installer3840.apk', 'installer3856.apk', 'installer3852.apk', 'installer3764.apk', 'installer3824.apk'}

    # apk_files = apk_files[55:]

    # Create output folders, if they don't exist.
    create_output_folders()

    start_time = time.time()

    # Run the tools on all the apk files.
    for apk in apk_files:

        # Check if the apk file is in the timeouts map.
        if apk in timeouts_map:
            # print(apk)
            run_flowdroid(apk)
        else:
            continue
        # run_apkid(apk)

        # Run apkleaks
        # run_apkleaks(apk)

        # Run dex2jar and dependency-check
        # run_d_check(apk)

        # Run mobsf
        # run_mobsf(apk)

        # Run flowdroid
        # run_flowdroid(apk)

    print("--- %s seconds ---" % (time.time() - start_time))