
# Internal network Scanner

This script performs various scans on a target IP address to gather information about its operating system, services, vulnerabilities, and web applications.


## Features

- Performs Nmap scans for OS detection, service version identification, and vulnerability detection
- Runs Nikto web vulnerability scanner
- Presents results in organized tables using PrettyTable
- Includes filters to remove irrelevant information from Nmap output


## Installation

## Usage/Examples

1. **Install the required Python libraries:**
   - [prettytable](https://pypi.org/project/prettytable/)
   - [nmap](https://pypi.org/project/python-nmap/)
   - [nikto](https://cirt.net/Nikto)

 ```
   pip install prettytable nmap nikto
 ```

2. **Modify the ```Target``` variable in the script to reflect the desired target.**

3. **Run the script:**
    ```
    python main.py
    ```
    
## Output

The script will display the following information for the target IP address:

- **Phase 1: OS Scan**
  - Table showing open ports, their state, and service name
  - Results obtained using the standard Nmap scan

- **Phase 2: OS Scan with -Pn**
  - Table showing open ports, their state, and service name
  - Results obtained using the Nmap scan with the -Pn flag for pingless detection

- **Phase 3: Service Version Scan**
  - Table showing open ports, their state, service name, and version
  - Results obtained using the Nmap scan with the -sV flag for service version detection

- **Phase 4: Nikto Scan**
  - Detailed output of Nikto scan, including identified vulnerabilities
  - Nikto helps identify potential web application security issues


Note: The specific output may vary depending on the target IP address and installed services.
