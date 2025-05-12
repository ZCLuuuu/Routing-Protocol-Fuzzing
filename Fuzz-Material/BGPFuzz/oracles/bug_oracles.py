import ipaddress
import pyshark
from prefix import get_prefix

def oracle_duplicate_prefix(telnet_port):
    raw = get_prefix(telnet_port)
    prefixes = [ipaddress.IPv4Network(p) for p in raw if p]
    suspicious = []
    for i in range(len(prefixes)):
        for j in range(len(prefixes)):
            if i != j and prefixes[i].subnet_of(prefixes[j]) and prefixes[i] != prefixes[j]:
                suspicious.append((str(prefixes[j]), str(prefixes[i])))
    if suspicious:
        print("[!] Duplicate prefix pattern detected:")
        for s, sub in suspicious:
            print(f" - {sub} is a sub-prefix of {s}")
        return True, suspicious
    return False, []


def oracle_scan_pcap_file(file_path):
    print(f"Scanning {file_path} for BGP UPDATE packets...")

    try:
        capture = pyshark.FileCapture(file_path, display_filter="bgp.type == 3")

        for packet in capture:
            print("\033[94m[+] BGP UPDATE packet found!\033[0m")
            print(packet)
        
        capture.close()
        print("Oracle 1: Scan complete.\n")

    except Exception as e:
        display_error_ansi(f"An error occurred while scanning: {e}")

def display_error_ansi(message):
    """Print an error message in red using ANSI escape codes."""
    print(f"\033[91m{message}\033[0m")