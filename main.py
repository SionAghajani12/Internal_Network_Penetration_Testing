from Internal_Network_Scanning import run_nmap_os_scan, run_nmap_service_version_scan,run_nmap_os_scan_pn
from vulnerability_scanning import run_nikto

def main():
    target_ip = '167.71.2.116'

    # Run OS scan Phase 1
    os_scan_result = run_nmap_os_scan(target_ip)
    print("OS Scan Result:")
    print(os_scan_result)
    print("-" * 50)

    # Run OS scan with -Pn Phase 2
    os_scan_pn_result = run_nmap_os_scan_pn(target_ip)
    print("Scan Result with -Pn:")
    print(os_scan_pn_result)
    print("-" * 50)

    # Run service version scan Phase 3
    service_version_result = run_nmap_service_version_scan(target_ip)
    print("Service Version Scan Result:")
    print(service_version_result)
    print("-" * 50)

    # Run Nikto for vulnerability scanning Phase 4
    nikto_result = run_nikto(target_ip)
    print("Nikto Scan Result:")
    print(nikto_result)
    print("-" * 50)

if __name__ == "__main__":
    main()