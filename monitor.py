from scapy.all import sniff, TCP, IP
import platform
import psutil
import socket
import os


def extract_http_host(packet):
    try:
        if packet.haslayer('Raw') and packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            dst_ip = packet[IP].dst

            web_ports = [80, 443, 8080, 8443]
            if dst_port in web_ports:
                payload = packet['Raw'].load

                # HTTP traffic
                if dst_port == 80 or dst_port == 8080:
                    if "Host:" in payload.decode(errors='ignore'):
                        host_line = [line for line in payload.decode(errors='ignore').splitlines() if line.startswith("Host:")]
                        if host_line:
                            print(f"HTTP Website: {host_line[0].split()[1]}")

                # HTTPS traffic
                elif dst_port == 443 or dst_port == 8443:
                    #print(f"Raw Payload (HTTPS): {payload}")
                    if b'\x16\x03' in payload: # TLS handshake
                        sni = extract_sni_from_tls(payload)
                        if sni:
                            print(f"HTTPS Website (SNI): {sni}")
                        else:
                            try:
                                hostname = socket.gethostbyaddr(dst_ip)[0]
                                print(f"HTTPS Resolved Hostname: {hostname}")
                            except socket.herror:
                                print(f"HTTPS Resolved Hostname: Could not resolve hostname for IP {dst_ip}")
                    else:
                        #print(f"Encrypted HTTPS Payload: {payload[:50]}...")
                        pass
    except Exception as e:
        print(f"Error: {e}")


def extract_sni_from_tls(payload):
    try:
        if payload[0] == 22:
            extensions = payload.split(b'\x00\x17') # SNI
            if len(extensions) > 1:
                sni = extensions[1][1:].split(b'\x00')[0]
                return sni.decode(errors='ignore')
    except Exception:
        pass
    return None


# Just in case I need to log packets
def log_unresolved_packet(payload):
    with open("unresolved_packets.log", "a") as log_file:
        log_file.write(f"Unresolved Payload: {payload}\n")


def detect_network_interfaces():
    interfaces = []
    if platform.system() == "Windows":
        adapters = psutil.net_if_addrs()
        for adapter in adapters:
            interfaces.append(adapter)
    else:
        adapters = os.listdir('/sys/class/net/')
        for adapter in adapters:
            if adapter != "lo": # Skip loopback
                interfaces.append(adapter)
    return interfaces


def start_sniffing(interfaces):
    print(f"Listening on interfaces: {', '.join(interfaces)}...")
    for interface in interfaces:
        sniff(iface=interface, prn=extract_http_host, filter="tcp", store=0, count=0)


if __name__ == "__main__":
    interfaces = detect_network_interfaces()
    if not interfaces:
        print("No network interfaces detected.")
    else:
        print("Detected network interfaces:")
        for i, interface in enumerate(interfaces):
            print(f"{i + 1}. {interface}")
        
        sniff_all = input("Do you want to sniff on all interfaces? (y/n): ").strip().lower()
        if sniff_all == 'y':
            start_sniffing(interfaces)
        else:
            selected = int(input("Select an interface by number: ")) - 1
            if 0 <= selected < len(interfaces):
                start_sniffing([interfaces[selected]])
            else:
                print("Invalid selection.")
