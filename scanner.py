import socket
import time
import sys
from datetime import datetime


def check_http(port):
    try:
        sock = socket.create_connection((ip, port), timeout=1)

        request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        sock.sendall(request)

        response = sock.recv(1024)

        sock.close()

        if response.startswith(b"HTTP/"):
            return True

    except (socket.timeout, OSError):
        pass

    return False


def get_http_headers(port):
    try:
        sock = socket.create_connection((ip, port), timeout=1)

        request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        sock.sendall(request)

        response = sock.recv(4096)

        sock.close()

        return response.decode(errors="ignore")

    except (socket.timeout, OSError):
        return ""


def check_security_headers(headers):
    security_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy"
    ]

    for header in security_headers:
        if header.lower() in headers.lower():
            print("  Security Header :", header, "PRESENT")
        else:
            print("  Security Header :", header, "MISSING")


def assess_risk(port, service, headers=""):
    if service != "HTTP":
        return "UNKNOWN"

    missing = 0

    security_headers = [
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy"
    ]

    for header in security_headers:
        if header.lower() not in headers.lower():
            missing += 1

    if missing == 0:
        return "LOW"

    if missing == 1:
        return "MEDIUM"

    return "HIGH"


def scan_ports():
    results = []
    open_ports = 0

    ports = range(8000, 8021)

    for port in ports:
        sock = socket.socket()

        start = time.perf_counter()

        result = sock.connect_ex((ip, port))

        end = time.perf_counter()

        duration = round((end - start) * 1000, 2)

        if result == 0:
            open_ports += 1

            service = "HTTP" if check_http(port) else "Unknown"

            headers = ""

            if service == "HTTP":
                headers = get_http_headers(port)

            risk = assess_risk(port, service, headers)

            print("Port", port, "→ OPEN →", duration, "ms")

            if service == "HTTP":
                print("  Service : HTTP")

                if "Server:" in headers:
                    for line in headers.splitlines():
                        if line.startswith("Server:"):
                            print(
                                "  Serveur :",
                                line.split(":", 1)[1].strip()
                            )

                check_security_headers(headers)

            results.append(
                (port, duration, service, risk, headers)
            )

        sock.close()

    return results, open_ports


# ----------------------------
# Programme principal
# ----------------------------

if len(sys.argv) > 1:
    target = sys.argv[1]
else:
    target = input("Target : ")

try:
    ip = socket.gethostbyname(target)
except socket.gaierror:
    print("[ERREUR] Impossible de résoudre la cible.")
    exit()

print("CYBER SECURITY SCANNER")
print("======================")
print()
print("Target :", target)
print("IP     :", ip)
print()
print("PORT SCAN")
print("---------")

results, open_ports = scan_ports()

print()
print("Ports ouverts :", open_ports)

scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

overall_risk = "LOW"

for result in results:
    risk = result[3]

    if risk == "HIGH":
        overall_risk = "HIGH"
        break

    elif risk == "MEDIUM":
        overall_risk = "MEDIUM"

with open("scan_report.txt", "w") as file:
    file.write("CYBER SECURITY SCANNER\n")
    file.write("======================\n")
    file.write(f"Target : {target}\n")
    file.write(f"IP     : {ip}\n")
    file.write(f"Date   : {scan_time}\n")
    file.write(f"Ports ouverts : {open_ports}\n")
    file.write(f"Overall Risk  : {overall_risk}\n")
    file.write("\nPORT SCAN\n")
    file.write("---------\n")

    for port, duration, service, risk, headers in results:
        file.write(f"Port {port} → OPEN → {duration} ms\n")
        file.write(f"  Service : {service}\n")
        file.write(f"  Risk : {risk}\n")

        if service == "HTTP":
            file.write("  Security Headers:\n")

            for header in [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy"
            ]:
                if header.lower() in headers.lower():
                    file.write(f"    {header} : PRESENT\n")
                else:
                    file.write(f"    {header} : MISSING\n")

    file.write(f"\nPorts ouverts : {open_ports}\n")
    file.write("\nSCAN COMPLETE\n")
