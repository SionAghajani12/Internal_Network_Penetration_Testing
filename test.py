import argparse
from prettytable import PrettyTable
from Internal_Network_Scanning import run_nmap_service_version_scan, run_nmap_os_scan, run_nmap_os_scan_pn
from vulnerability_scanning import run_nikto
import subprocess
import requests

def create_table(header, data):
    table = PrettyTable()
    table.field_names = header
    for row in data:
        table.add_row(row)
    return str(table)

def is_ip_responsive(ip):
    try:
        subprocess.run(["ping", "-c", "1", ip], check=True, stdout=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def run_os_scan(ip):
    if not is_ip_responsive(ip):
        print(f"{ip} is not responsive. Skipping...")
        return

    os_scan_result = run_nmap_os_scan(ip)
    os_table_header = ['PORT', 'STATE', 'SERVICE']
    os_table_data = []

    if "PORT" in os_scan_result:
        print(f"{ip} OS Scan Result:")
        relevant_lines = False

        for line in os_scan_result.split('\n'):
            if "PORT" in line and "STATE" in line and "SERVICE" in line:
                relevant_lines = True
                continue
            elif not line.strip() or "unrecognized" in line.lower() or "fingerprint" in line.lower():
                relevant_lines = False

            if relevant_lines:
                fields = line.split()
                if len(fields) >= 3:
                    port = fields[0]
                    state = fields[1]
                    service = fields[2]
                    os_table_data.append([port, state, service])

        os_table = create_table(os_table_header, os_table_data)
        print(os_table)
        print("-" * 50)

def run_os_scan_pn(ip):
    if not is_ip_responsive(ip):
        print(f"{ip} is not responsive. Skipping...")
        return

    os_scan_pn_result = run_nmap_os_scan_pn(ip)
    os_pn_table_header = ['PORT', 'STATE', 'SERVICE']
    os_pn_table_data = []

    if "PORT" in os_scan_pn_result:
        print(f"{ip} Scan Result with -Pn:")
        relevant_lines = False

        for line in os_scan_pn_result.split('\n'):
            if "PORT" in line and "STATE" in line and "SERVICE" in line:
                relevant_lines = True
                continue
            elif not line.strip() or "unrecognized" in line.lower() or "fingerprint" in line.lower():
                relevant_lines = False

            if relevant_lines:
                fields = line.split()
                if len(fields) >= 3:
                    port = fields[0]
                    state = fields[1]
                    service = fields[2]
                    os_pn_table_data.append([port, state, service])

        os_pn_table = create_table(os_pn_table_header, os_pn_table_data)
        print(os_pn_table)
        print("-" * 50)

def run_service_version_scan(ip):
    if not is_ip_responsive(ip):
        print(f"{ip} is not responsive. Skipping...")
        return

    service_version_result = run_nmap_service_version_scan(ip)
    service_version_table_header = ['PORT', 'STATE', 'SERVICE', 'VERSION']
    service_version_table_data = []

    if "PORT" in service_version_result:
        print(f"{ip} Service Version Scan Result:")
        relevant_lines = False

        for line in service_version_result.split('\n'):
            if "PORT" in line and "STATE" in line and "SERVICE" in line and "VERSION" in line:
                relevant_lines = True
                continue
            elif not line.strip() or "unrecognized" in line.lower() or "fingerprint" in line.lower():
                relevant_lines = False

            if relevant_lines:
                fields = line.split()
                if len(fields) >= 4:
                    port = fields[0]
                    state = fields[1]
                    service = fields[2]
                    version = ' '.join(fields[3:])
                    service_version_table_data.append([port, state, service, version])

        service_version_table = create_table(service_version_table_header, service_version_table_data)
        print(service_version_table)
        print("-" * 50)

def run_nikto_scan(ip):
    if not is_ip_responsive(ip):
        print(f"{ip} is not responsive. Skipping...")
        return

    nikto_result = run_nikto(ip)
    
    if "Not Found" not in nikto_result:
        print(f"{ip} Nikto Scan Result:")
        print(nikto_result)
        print("-" * 50)
        if any(port in nikto_result for port in ['80', '8080', '443', '8000', '8443', '3000', '5000', '3128']):
            print(f"Found specific vulnerability on {ip}")
        else:
            print("No specific vulnerability found.")

def main():
    parser = argparse.ArgumentParser(description='Network scanning and vulnerability assessment tool')
    parser.add_argument('-ph', '--phase', type=int, help='Specify the phase number to run (e.g., -ph 1)')
    parser.add_argument('-A', '--all_phases', action='store_true', help='Run all phases')

    args = parser.parse_args()

    subnet = '10.0.0.0/24'
    total_ips = 255

    for i in range(1, total_ips + 1):
        target_ip = f'{subnet[:-4]}{i}'

        progress_percentage = (i / total_ips) * 100
        print(f"\nProgress: {progress_percentage:.2f}% - IP: {target_ip}")

        if args.all_phases:
            if is_ip_responsive(target_ip):
                run_os_scan(target_ip)
                run_os_scan_pn(target_ip)
                run_service_version_scan(target_ip)
                run_nikto_scan(target_ip)
            else:
                print(f"{target_ip} is not responsive. Skipping...")
        elif args.phase:
            if args.phase == 1:
                run_os_scan(target_ip)
            elif args.phase == 2:
                run_os_scan_pn(target_ip)
            elif args.phase == 3:
                run_service_version_scan(target_ip)
            elif args.phase == 4:
                run_nikto_scan(target_ip)
        else:
            print("Please specify a phase using -ph or use -A to run all phases.")

if __name__ == "__main__":
    main()
