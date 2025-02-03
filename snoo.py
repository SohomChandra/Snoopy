import scapy.all as scapy
import socket
import subprocess
import platform
import nmap
import sys
from typing import List, Dict

def get_default_gateway() -> str:
    """Find the default gateway IP address of the network."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("ipconfig", shell=True, timeout=5).decode()
            for line in output.split('\n'):
                if "Default Gateway" in line:
                    gateway = line.split(':')[-1].strip()
                    if gateway:
                        return gateway
            raise ValueError("Default gateway not found")
        else:
            output = subprocess.check_output("ip route", shell=True, timeout=5).decode()
            return output.split("default via ")[1].split()[0]
    except (subprocess.SubprocessError, IndexError, ValueError) as e:
        print(f"Error getting default gateway: {e}")
        sys.exit(1)

def scan_network(network_range: str) -> List[Dict[str, str]]:
    """Scan the network and retrieve IP, MAC (BSSID), and hostname."""
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print("Error: Nmap not found or insufficient permissions")
        sys.exit(1)
    
    devices = []
    try:
        nm.scan(hosts=network_range, arguments="-sn")  # Ping sweep
        
        for host in nm.all_hosts():
            ip = host
            mac = nm[host]["addresses"].get("mac", "Unknown")
            
            # Set timeout for hostname lookup
            socket.setdefaulttimeout(2)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.timeout):
                hostname = "Unknown"
            
            devices.append({
                "IP": ip,
                "BSSID": mac,
                "Hostname": hostname
            })
            
        return devices
    except Exception as e:
        print(f"Error during network scan: {e}")
        sys.exit(1)

def main():
    try:
        gateway = get_default_gateway()
        network_range = f"{gateway}/24"
        print(f"Scanning network: {network_range}\n")
        
        devices = scan_network(network_range)
        
        print("Connected Devices:")
        print("IP Address\t\tBSSID (MAC)\t\tHostname")
        print("-" * 50)
        
        for device in devices:
            print(f"{device['IP']}\t{device['BSSID']}\t{device['Hostname']}")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()