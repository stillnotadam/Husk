import sys, json
from husk.package_scanner import scan_package
f = scan_package(sys.argv[1]); print(json.dumps({"flagged": bool(f), "n": len(f), "findings": f[:20]}))
