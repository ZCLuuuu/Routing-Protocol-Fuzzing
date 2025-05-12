import subprocess
import re
import ipaddress
import tempfile
import os

def get_vm_path():
    result = subprocess.run(["vmrun", "list"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if line.strip().endswith(".vmx"):
            return line.strip()
    return None

def get_vm_ip(vmx_path):
    result = subprocess.run(["vmrun", "getGuestIPAddress", vmx_path], capture_output=True, text=True)
    return result.stdout.strip()

def run_expect_telnet(vm_ip, port, log_path):
    print("we are after 10000")
    expect_script = f"""
#!/usr/bin/expect -f
set timeout 10
set host "{vm_ip}"
set port "{port}"

log_file -noappend {log_path}

spawn telnet $host $port

# Try sending Enter multiple times until we see the prompt
set tries 10
while {{ $tries > 0 }} {{
    send "\\r"
    expect {{
        "#" {{ break }}
        timeout {{ incr tries -1 }}
    }}
}}

after 100000
expect "#"
send "show ip bgp\\r"
expect "#"
send "show ip bgp\\r"
expect "#"
send "show ip bgp\\r"
expect "#"
send "show ip bgp\\r"
expect "#"
send "show ip bgp\\r"
expect "#"
send "show ip bgp\\r"
expect "#"
send "show ip bgp\\r"

expect "#"
send "exit\\r"
"""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".exp") as f:
        f.write(expect_script)
        script_path = f.name

    os.chmod(script_path, 0o755)
    subprocess.run(["expect", script_path])
    os.remove(script_path)


def extract_prefixes(log_path):
    prefixes = set()

    # Match entries like: *> 10.0.1.0/30 OR *> 208.65.153.0 (no mask)
    bgp_line_pattern = re.compile(
        r'^\s*[r\*]?>?\s+(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?', re.IGNORECASE
    )

    with open(log_path, "r") as f:
        for line in f:
            match = bgp_line_pattern.match(line)
            if match:
                ip = match.group(1)
                mask = match.group(2)
                if mask:
                    prefix = f"{ip}{mask}"
                else:
                    prefix = f"{ip}/24"  # Default to /24 if no mask

                try:
                    ip_net = ipaddress.IPv4Network(prefix, strict=False)
                    prefixes.add(str(ip_net))
                except Exception as e:
                    print(f"Warning: Skipping invalid prefix {prefix} ({e})")

    return sorted(prefixes)

def get_prefix(telnet_port):
    # Note: we didn't check if it is GNS3 VM

    vmx_path = get_vm_path()
    if not vmx_path:
        print("No running VMs found.")
        return
    print(f"[+] Found VM: {vmx_path}")

    vm_ip = get_vm_ip(vmx_path)
    if not vm_ip:
        print("[-] Failed to get VM IP address.")
        return
    print(f"[+] VM IP: {vm_ip}")

    print("[*] Launching Telnet and sending 'show ip bgp'...")
    run_expect_telnet(vm_ip, telnet_port, "bgp_output.log")

    print("[*] Extracting BGP prefixes from log...")
    prefixes = extract_prefixes("bgp_output.log")

    if prefixes:
        print("[+] Prefixes found:")
        for pfx in prefixes:
            print(f"  - {pfx}")
        return prefixes
    else:
        print("[-] No BGP prefixes found.")