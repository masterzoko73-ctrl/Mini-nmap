import socket
import threading
import queue

def detect_service_by_banner(banner):
    text = banner.decode("utf-8", errors="ignore").lower()

    if "http" in text:
        return "http"
    if "ssh" in text:
        return "ssh"
    if "ftp" in text:
        return "ftp"
    if "smtp" in text or "220" in text:
        return "smtp"
    if "pop3" in text:
        return "pop3"
    if "imap" in text:
        return "imap"
    if "mysql" in text:
        return "mysql"
    if "postgres" in text or "psql" in text:
        return "postgresql"
    if "redis" in text:
        return "redis"
    if "telnet" in text:
        return "telnet"
    if "ldap" in text:
        return "ldap"
    if "microsoft" in text or "windows" in text:
        return "microsoft"

    return "unknown"


def get_service(sock, port):
    try:
        service_name = socket.getservbyport(port, "tcp")
    except OSError:
        service_name = "unknown"

    try:
        sock.settimeout(1.0)

        probes = {
            21: b"QUIT\r\n",
            25: b"EHLO localhost\r\n",
            80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            443: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            110: b"USER test\r\n",
            143: b"CAPABILITY\r\n",
            3306: b"\r\n",
            6379: b"INFO\r\n",
        }

        probe = probes.get(port)

        if probe is not None:
            try:
                sock.sendall(probe)
            except OSError:
                pass

        banner = b""

        try:
            while True:
                chunk = sock.recv(1024)

                if not chunk:
                    break

                banner += chunk

                if len(banner) >= 1024:
                    break

        except socket.timeout:
            pass

        if banner:
            detected = detect_service_by_banner(banner)

            if detected != "unknown":
                return detected

    except OSError:
        pass

    return service_name


def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)

    try:
        result = sock.connect_ex((ip, port))

        if result == 0:
            return sock

        sock.close()
        return None

    except OSError:
        sock.close()
        return None


def worker(ip, work_queue, open_ports):
    while True:
        port = work_queue.get()

        if port is None:
            work_queue.task_done()
            break

        sock = scan_port(ip, port)

        if sock is not None:
            try:
                service = get_service(sock, port)
                open_ports.append((port, "open", service))
            finally:
                sock.close()

        work_queue.task_done()


def main():
    target = input("Target: ").strip()

    hostname = target
    ports_to_scan = list(range(1, 1025))

    if ":" in target:
        hostname, port_str = target.rsplit(":", 1)

        try:
            port = int(port_str)
        except ValueError:
            print("Invalid port value.")
            return

        if not (1 <= port <= 65535):
            print("Invalid port value. Please enter a valid port between 1 and 65535.")
            return

        hostname = hostname.strip()
        ports_to_scan = [port]

        print(f"Host: {hostname}")
        print(f"Port: {port}")

    else:
        hostname = hostname.strip()
        print(f"Host: {hostname}")
        print("Using default port range: 1-1024")

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        print("Invalid IP address or domain.")
        return

    open_ports = []

    work_queue = queue.Queue()

    for port in ports_to_scan:
        work_queue.put(port)

    threads = []
    worker_count = min(10, len(ports_to_scan))

    for _ in range(worker_count):
        thread = threading.Thread(
            target=worker,
            args=(ip, work_queue, open_ports)
        )
        threads.append(thread)
        thread.start()

    work_queue.join()

    for _ in range(worker_count):
        work_queue.put(None)

    for thread in threads:
        thread.join()

    print("PORT       STATE      SERVICE")

    for port, state, service in open_ports:
        print(f"{port}/tcp {state} {service}")


main()