import os
import sys
import subprocess
from mobsftester import *

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
    subprocess.call(apkid_cmd, shell = True)

def run_apkleaks(_name):
    """
    Runs apkleaks on the apk file.
    """
    print(f"Running apkleaks on apps/{_name}")

    # Run apkleaks
    apkleaks_cmd = f"apkleaks -f apps/{_name} -o apkleaks_output/{_name[:-4]}_apkleaks.txt"
    subprocess.call(apkleaks_cmd, shell = True)

def run_d_check(_name):
    """
    Runs dependency-check on the jar file.
    """
    print(f"Running dex2jar and dependency-check on {_name}")

    # Run dex2jar
    d2j_cmd = f"d2j-dex2jar apps/{_name} -o temp_jar/{_name[:-4]}.jar"
    subprocess.call(d2j_cmd, shell = True)

    # Run dependency-check
    d_check_cmd_json = f"dependency-check -s temp_jar/{_name[:-4]}.jar -f JSON -o dependencycheck_output/{_name[:-4]}"
    subprocess.call(d_check_cmd_json, shell = True)
    d_check_cmd_html = f"dependency-check -s temp_jar/{_name[:-4]}.jar -f HTML -o dependencycheck_output/{_name[:-4]}"
    subprocess.call(d_check_cmd_html, shell = True)

# def run_flowdroid(_name):
    # """
    # Runs flowdroid on the apk file.
    # """
    # print(f"Running flowdroid on {_name}")

    # # Run flowdroid
    # flowdroid_cmd = f"flowdroid -i {_name} -o flowdroid_output/{_name[:-4]}_flowdroid.txt"
    # subprocess.call(flowdroid_cmd, shell = True)

def run_mobsf(_name):
    """
    Runs mobsf on the apk file.
    """
    RESP = upload(f"apps/{_name}")
    scan(RESP)
    json_resp(RESP)
    pdf(RESP, _name[:-4])

def create_output_folders():
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
    apk_files = [f for f in os.listdir("apps/") if f.endswith(".apk")]

    # Create output folders, if they don't exist.
    create_output_folders()

    # Run the tools on all the apk files.
    for apk in apk_files:
        run_apkid(apk)
        run_apkleaks(apk)
        run_d_check(apk)
        run_mobsf(apk)
