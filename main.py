# main.py

from prettytable import PrettyTable
from Internal_Network_Scanning import run_nmap_service_version_scan, run_nmap_os_scan, run_nmap_os_scan_pn
from vulnerability_scanning import run_nikto

def create_table(header, data):
    table = PrettyTable()
    table.field_names = header
    for row in data:
        table.add_row(row)
    return str(table)

def main():
    target_ip = '10.0.0.3'

    # Run OS scan Phase 1
    os_scan_result = run_nmap_os_scan(target_ip)
    os_table_header = ['PORT', 'STATE', 'SERVICE']
    os_table_data = []

    print(f"{target_ip} OS Scan Result:")
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

    # Run OS scan with -Pn Phase 2
    os_scan_pn_result = run_nmap_os_scan_pn(target_ip)
    os_pn_table_header = ['PORT', 'STATE', 'SERVICE']
    os_pn_table_data = []

    print(f"{target_ip} Scan Result with -Pn:")
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

    # Run service version scan Phase 3
    service_version_result = run_nmap_service_version_scan(target_ip)
    service_version_table_header = ['PORT', 'STATE', 'SERVICE', 'VERSION']
    service_version_table_data = []

    # Extracting relevant information from the service version scan result
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
    print(f"{target_ip} Service Version Scan Result:")
    print(service_version_table)
    print("-" * 50)

    nikto_result = run_nikto(target_ip)
    print(f"{target_ip}Nikto Scan Result:")
    print(nikto_result)
    print("-" * 50)

if __name__ == "__main__":
    main()
