# Simulates a hanging/resource-abuse pattern (harmless in itself - an
# infinite loop with no side effects - used only to verify the sandbox's
# timeout and CPU-limit enforcement actually stop it).
while True:
    pass
