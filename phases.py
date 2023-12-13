from Internal_Network_Scanning import run_nmap_service_version_scan, run_nmap_os_scan, run_nmap_os_scan_pn,run_nmap_os_scan_for_port
from vulnerability_scanning import run_nikto
from checking_ports import is_port_responsive,check_and_print_port_status
from ip_and_ping import is_ip_responsive
from table import create_table

def phase_1(ip):
    ping_result = is_ip_responsive(ip)
    print(f"{ip} is {'responsive' if ping_result else 'unresponsive'}.")
    return ping_result

def phase_2(ip, port=None):
    if is_ip_responsive(ip):
        if port is None:
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
                            scanned_port = fields[0]
                            state = fields[1]
                            service = fields[2]
                            os_table_data.append([scanned_port, state, service])

                os_table = create_table(os_table_header, os_table_data)
                print(os_table)
                print("-" * 50)
        else:
            os_scan_result = run_nmap_os_scan_for_port(f"{ip}:{port}")
            os_table_header = ['PORT', 'STATE', 'SERVICE']
            os_table_data = []

            if "PORT" in os_scan_result:
                print(f"{ip} OS Scan Result for Port {port}:")
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
                            scanned_port = fields[0]
                            state = fields[1]
                            service = fields[2]
                            os_table_data.append([scanned_port, state, service])

                os_table = create_table(os_table_header, os_table_data)
                print(os_table)
                print("-" * 50)





def phase_3(ip, port=None):
    if is_ip_responsive(ip):
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
                        scanned_port = fields[0]
                        state = fields[1]
                        service = fields[2]
                        os_pn_table_data.append([scanned_port, state, service])

            os_pn_table = create_table(os_pn_table_header, os_pn_table_data)
            print(os_pn_table)
            print("-" * 50)

        if port:
            # Check the specific port
            check_and_print_port_status(ip, port)



def phase_4(ip):
    if is_ip_responsive(ip):
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
#DO NOT TOUCH PHASE 5 ITSSSSS WOOOORKINNNGGG
def phase_5(ip, port=None):
    if is_ip_responsive(ip):
        if port is None:
            nikto_result = run_nikto(ip, ports='80,8080,443,8000,8443,3000,5000,3128')
            print(nikto_result)
        else:
            is_port_open = is_port_responsive(ip, port)
            if is_port_open:
                run_nikto(ip)
                # Add your specific result for this port here
    else:
        print(f"{ip} is unresponsive. Cannot perform Nikto scan or check specific port.")