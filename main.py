import argparse
from ip_and_ping import generate_ip_list
from phases import phase_1, phase_2, phase_3, phase_4, phase_5

def main():
    parser = argparse.ArgumentParser(description="Network Scanning Phases")
    parser.add_argument("--ip", help="Specify either a subnet (e.g., '10.0.0.0/24') or a single IP address")
    parser.add_argument("-p", "--phase", type=int, choices=range(1, 6), help="Specify the scanning phase (1 to 5)")
    parser.add_argument("-P", "--port", default="", help="Specify the port for phase 5")

    args = parser.parse_args()
    target = args.ip

    if "/" in target:  # Subnet provided
        ip_list = generate_ip_list(target)
    else:  # Single IP address provided
        ip_list = [target]

    for ip in ip_list:
        if args.phase:
            if args.phase == 1:
                phase_1(ip)
            elif args.phase == 2:
                phase_2(ip, args.port)
            elif args.phase == 3:
                phase_3(ip)
            elif args.phase == 4:
                phase_4(ip)
            elif args.phase == 5:
                phase_5(ip, args.port)
            else:
                print("Invalid phase specified. Use -h for help.")
        else:
            print("Error: Please specify a scanning phase using the -p option.")

if __name__ == "__main__":
    main()
