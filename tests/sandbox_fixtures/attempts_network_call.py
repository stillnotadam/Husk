# Simulates an exfiltration attempt (a real attack would send data out;
# this only tries to connect, with no actual payload, to verify the
# sandbox's network isolation actually blocks it at the kernel level).
import socket
try:
    socket.create_connection(("8.8.8.8", 53), timeout=3)
    print("NETWORK_CALL_SUCCEEDED")
except OSError as e:
    print(f"NETWORK_CALL_BLOCKED: {e}")
