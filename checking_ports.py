import socket


def is_port_responsive(ip, port):
    try:
        with socket.create_connection((ip, int(port)), timeout=1) as sock:
            print(f"Port {port} is open on {ip}")
            return True
    except (socket.timeout, socket.error):
        print(f"No web server found on {ip}:{port}")
        return False


def check_and_print_port_status(ip, port):
    try:
        with socket.create_connection((ip, int(port)), timeout=1) as sock:
            print(f"Port {port} is open on {ip}")
    except (socket.timeout, socket.error):
        print(f"Port {port} is closed on {ip}")