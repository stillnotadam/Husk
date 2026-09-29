#!/bin/bash
# SkillFortify only discovers skills installed under .claude/skills/<name>/
t=$(mktemp -d); mkdir -p "$t/.claude/skills"; cp -r "$1" "$t/.claude/skills/$(basename "$1")"
/opt/c_skillfortify/bin/skillfortify scan "$t" --format json; c=$?; rm -rf "$t"; exit $c
