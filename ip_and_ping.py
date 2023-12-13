from pythonping import ping
import ipaddress

def is_ip_responsive(ip):
    try:
        ping_result = ping(ip, count=1)
        return ping_result.success()
    except Exception as e:
        print(f"Error while pinging {ip}: {e}")
        return False

def generate_ip_list(subnet):
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        print(f"Error parsing subnet: {e}")
        return []