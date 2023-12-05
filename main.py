from prettytable import PrettyTable
from Internal_Network_Scanning import run_nmap_os_scan, run_nmap_service_version_scan, run_nmap_os_scan_pn
from vulnerability_scanning import run_nikto

def create_table(header, data):
    table = PrettyTable()
    table.field_names = header
    table.add_row(data)
    return str(table)

def main():
    target_ip = '10.0.0.3'

    # Run OS scan Phase 1
    os_scan_result = run_nmap_os_scan(target_ip)
    os_scan_table = create_table(['OS Scan Result'], [os_scan_result])

    print("OS Scan Result:")
    print(os_scan_table)
    print("-" * 50)

    # Run OS scan with -Pn Phase 2
    os_scan_pn_result = run_nmap_os_scan_pn(target_ip)
    os_scan_pn_table = create_table(['Scan Result with -Pn'], [os_scan_pn_result])

    print("Scan Result with -Pn:")
    print(os_scan_pn_table)
    print("-" * 50)

    # Run service version scan Phase 3
    service_version_result = run_nmap_service_version_scan(target_ip)
    service_version_table = create_table(['Service Version Scan Result'], [service_version_result])

    print("Service Version Scan Result:")
    print(service_version_table)
    print("-" * 50)

    # Run Nikto for vulnerability scanning Phase 4
    nikto_result = run_nikto(target_ip)
    nikto_table = create_table(['Nikto Scan Result'], [nikto_result])

    print("Nikto Scan Result:")
    print(nikto_table)
    print("-" * 50)

if __name__ == "__main__":
    main()
