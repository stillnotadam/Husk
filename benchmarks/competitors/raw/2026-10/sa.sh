#!/bin/bash
t=$(mktemp -d)/r.json
$HOME/cvenv/secureai/node_modules/.bin/secureai-scan skill "$1" --severity low --output "$t" >/dev/null 2>&1
c=$?; cat "$t" 2>/dev/null; rm -rf "$(dirname "$t")"; exit $c
