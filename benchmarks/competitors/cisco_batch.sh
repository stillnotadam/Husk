cd /home/claude/cbench
s=$(date +%s)
/opt/c_cisco_ai_skill_scanner/bin/skill-scanner scan-all /home/claude/cbench/stage_small --format json --lenient > cisco_batch.json 2> cisco_batch.err
echo "rc=$? secs=$(( $(date +%s) - s ))" > cisco_batch.done
