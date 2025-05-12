#!/usr/bin/env

import json
import subprocess

# Run the dnscrypt-proxy command and capture the output
command = ["dnscrypt-proxy", "-list", "-json", "-config", "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"]
result = subprocess.run(command, capture_output=True, text=True)

# Extract the JSON portion from the output
output = result.stdout
json_start = output.find("[")  # Find the start of the JSON array
json_end = output.rfind("]") + 1  # Find the end of the JSON array
json_data = output[json_start:json_end]

# Parse the JSON data
try:
    servers = json.loads(json_data)
except json.JSONDecodeError as e:
    exit(1)

# Extract IP addresses from the "addrs" field
ip_addresses = []
for server in servers:
    if "addrs" in server:
        ip_addresses.extend(server["addrs"])

# Print the list of IP addresses
for ip in ip_addresses:
    print(ip)