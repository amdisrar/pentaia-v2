from pentaia.nmap_wrapper import nmap_scan


stdout, stderr, exit_code = nmap_scan("172.16.0.13")

print("STDOUT:")
print(stdout)

print("\nSTDERR:")
print(stderr)

print("\nEXIT CODE:")
print(exit_code)
