import os
import subprocess


def run_nmap_vuln_script(ip_address):
    script_directory = os.path.dirname(os.path.abspath(__file__))
    vulscan_script_path = os.path.join(script_directory, 'scipag_vulscan', 'vulscan.nse')

    command = f'nmap -sV --script={vulscan_script_path} {ip_address}'

    try:
        # Run the Nmap command
        subprocess.run(command, shell=True)

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
