# Network Traffic Monitor

This script is a quick tool for monitoring network traffic and identifying HTTP and HTTPS websites visited on your local network. It utilizes 'Scapy' to sniff packets and analyze web traffic on common web ports.

---

## Features

- **HTTP Traffic**: Extracts and displays the 'Host' header from HTTP traffic on ports 80 and 8080.
- **HTTPS Traffic**: 
  - Attempts to extract the Server Name Indication (SNI) during the TLS handshake.
  - Falls back to resolving the hostname using reverse DNS if SNI is unavailable.
- **Support for Common Web Ports**: Monitors traffic on ports 80, 443, 8080, and 8443.
- **Cross-Platform**: Automatically detects network interfaces on both Windows and Linux.
- **Error Handling**: Gracefully handles exceptions and logs unresolved packets if needed.

---

## Limitations

- This script does **not** decrypt HTTPS traffic beyond the TLS handshake.
- Reverse DNS lookups may fail for some IPs if no PTR record exists.
- It is designed for quick traffic analysis and is **not** a comprehensive packet analyzer.

---

## Requirements

This script requires the following Python packages:

- 'scapy': For packet sniffing and analysis.
- 'psutil': For detecting network interfaces.
- 'socket': For DNS lookups (built-in Python module).

Install the necessary packages using 'pip':

'pip install scapy psutil'

---

## Usage

1. Run the script with administrator/root privileges (required for packet sniffing).
2. Select the network interface(s) you want to monitor or sniff on all interfaces.
3. The script will display the following:
   - HTTP website hosts.
   - HTTPS website SNI information or resolved hostnames (when available).

---

## Example Output

'Detected network interfaces:
1. eth0
2. wlan0
Do you want to sniff on all interfaces? (y/n): y
Listening on interfaces: eth0, wlan0...

HTTP Website: example.com
HTTPS Website (SNI): secure.example.com
HTTPS Resolved Hostname: api.example.com'

---

Keeping in mind all might break...

## Disclaimer

This script is a simple tool for network traffic inspection. Use it responsibly and only on networks you own or have permission to monitor. Unauthorized network monitoring is illegal in many jurisdictions.
