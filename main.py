import argparse
from prettytable import PrettyTable
from Internal_Network_Scanning import run_nmap_service_version_scan, run_nmap_os_scan, run_nmap_os_scan_pn
from vulnerability_scanning import run_nikto
from audit import run_nmap_vuln_script
from pythonping import ping
import subprocess 

def create_table(header, data):
    table = PrettyTable()
    table.field_names = header
    for row in data:
        table.add_row(row)
    return str(table)

def is_ip_responsive(ip):
    try:
        ping_result = ping(ip, count=1)
        return ping_result.success()
    except Exception as e:
        print(f"Error while pinging {ip}: {e}")
        return False

def perform_all_phases(ip):
    phase_1(ip)
    phase_2(ip)
    phase_3(ip)
    phase_4(ip)
    phase_5(ip)

def phase_1(ip):
    return is_ip_responsive(ip)

def phase_2(ip):
    if is_ip_responsive(ip):
        # Corrected function call to run OS scan
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

def phase_3(ip):
    if is_ip_responsive(ip):
        # Corrected function call to run OS scan with -Pn
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

def phase_4(ip):
    if is_ip_responsive(ip):
        # Corrected function call to run service version scan
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


def run_nikto(ip, ports=None):
    command = ["nikto", "-h", ip]

    if ports:
        command.extend(["-p", ports])

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Print Nikto output in real-time
        for line in iter(process.stdout.readline, ''):
            print(line.strip())

        process.stdout.close()
        return_code = process.wait()

        if return_code != 0:
            print(f"Error running Nikto on {ip}. Return code: {return_code}")

    except Exception as e:
        print(f"Error running Nikto on {ip}: {e}")

def phase_5(ip):
    if is_ip_responsive(ip):
        # Specify additional ports as needed
        nikto_result = run_nikto(ip, ports='80,8080,443,8000,8443,3000,5000,3128')
        if "Not Found" not in nikto_result:
            print(f"{ip} Nikto Scan Result:")
            print(nikto_result)
            print("-" * 50)
            # Check if any of the specified ports are found in the Nikto result
            if any(port in nikto_result for port in ['80', '8080', '443', '8000', '8443', '3000', '5000', '3128', '4000']):
                print(f"Found a specific vulnerability on {ip}")
                # Additional logic to handle the specific vulnerability found
                # You can customize this part based on the actual vulnerability
            else:
                print("No specific vulnerability found.")

def main():
    parser = argparse.ArgumentParser(description="Network Scanning Phases")
    parser.add_argument("target", help="Specify either a subnet (e.g., '10.0.0.0/24') or a single IP address")
    parser.add_argument("-p", "--phase", type=int, choices=range(1, 6), help="Specify the scanning phase (1 to 5)")
    parser.add_argument("-a", "--all", action="store_true", help="Perform all phases for each IP")

    args = parser.parse_args()
    target = args.target

    if "/" in target:  # Subnet provided
        ip_list = [f'{target[:-4]}{i}' for i in range(1, 255)]
    else:  # Single IP address provided
        ip_list = [target]

    for ip in ip_list:
        if args.all:
            perform_all_phases(ip)
        else:
            if args.phase == 1:
                phase_1(ip)
            elif args.phase == 2:
                phase_2(ip)
            elif args.phase == 3:
                phase_3(ip)
            elif args.phase == 4:
                phase_4(ip)
            elif args.phase == 5:
                phase_5(ip)
            else:
                print("Invalid phase specified. Use -h for help.")

if __name__ == "__main__":
    main()
