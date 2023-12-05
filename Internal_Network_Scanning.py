import subprocess

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

def run_nmap_service_version_scan(ip):
    cmd = ['nmap', '-sV', '--version-intensity', '5', ip]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


