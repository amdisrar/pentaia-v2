from pentaia.kali_executor import run_command


stdout, stderr, exit_code = run_command(
    "hostname && whoami && nmap --version | head -1"
)

print("STDOUT:")
print(stdout)

print("\nSTDERR:")
print(stderr)

print("\nEXIT CODE:")
print(exit_code)