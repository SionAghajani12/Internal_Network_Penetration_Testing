# Internal_Network_Scanning.py

import subprocess
from prettytable import PrettyTable

def run_nmap_os_scan(target):
    try:
        cmd = ['nmap', '-O', target]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        if "Host seems down" in e.output:
            print("Host seems down. Trying with -Pn flag...")
            return run_nmap_os_scan_pn(target)
        else:
            raise

def run_nmap_os_scan_pn(target):
    cmd = ['nmap', '-Pn', '-O', target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

# Add the new function for service version scanning
def run_nmap_service_version_scan(target):
    cmd = ['nmap', '-sV', '--version-intensity', '5', target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout
