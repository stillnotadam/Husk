"""
Husk - skill file scanner, module 1: whitespace inflation detection.

THE ATTACK THIS DEFENDS AGAINST
--------------------------------
Some skill scanners (especially ones that use an LLM to judge "is this
safe?") only read the first N characters or tokens of a file before
deciding. An attacker can exploit this by padding a file with a huge
block of blank lines or whitespace BEFORE the malicious content. The
scanner reads the harmless-looking beginning, runs out of context
budget, and never sees what's hiding after the padding.

This has been documented as a real, working bypass technique against
multiple production skill scanners (published research, June 2026).

THE DEFENSE
-----------
Two independent checks, neither of which depends on reading the whole
file with an LLM (which would just recreate the same weakness):

1. Flag any suspiciously large contiguous whitespace run. A legitimate
   skill file has no real reason to contain thousands of blank lines
   in a row - the size of the gap is itself the signal, before we even
   look at what's on either side of it.

2. Always scan the ENTIRE file for dangerous patterns, never just a
   prefix. This sounds obvious, but it's exactly the assumption the
   attack breaks in tools that silently truncate.
"""

import base64
import re
import sys
import unicodedata


def is_invisible_or_blank(line):
    """
    True if a line is empty, whitespace-only, OR made up entirely of
    invisible/zero-width Unicode characters (category 'Cf' - format
    characters like zero-width space). Attackers use these specifically
    because str.strip() doesn't treat them as whitespace, which let an
    earlier version of this scanner be fooled by unicode padding.
    """
    if line.strip() == "":
        return True
    return all(unicodedata.category(ch) == "Cf" or ch.isspace() for ch in line)

# A run of blank/whitespace-only lines at or beyond this length has no
# legitimate reason to exist in a skill file and is treated as padding.
SUSPICIOUS_WHITESPACE_RUN = 50  # consecutive blank lines

# Patterns worth flagging if found anywhere in the file - kept simple
# and readable on purpose; this is a starting rule set to expand later.
DANGEROUS_PATTERNS = [
    (r"\bcurl\s+.*\|\s*(sh|bash)\b", "Pipes a downloaded script directly into a shell"),
    (r"\bexec\s*\(", "Uses exec() - runs code built at runtime"),
    (r"\beval\s*\(", "Uses eval() - runs code built at runtime"),
    (r"base64\s+-d", "Decodes base64 - common way to hide a payload"),
    (r"\brm\s+-rf\s+/", "Destructive filesystem command"),
    (r"os\.system\s*\(", "Direct shell command execution"),
    (r"subprocess\.(Popen|call|run)\s*\(", "Spawns a subprocess"),
]


def find_whitespace_runs(text):
    """
    Returns a list of (start_line, length) for contiguous blank-line
    runs at or above the suspicious threshold.
    """
    findings = []
    lines = text.split("\n")
    run_start = None
    run_len = 0

    for i, line in enumerate(lines):
        if is_invisible_or_blank(line):
            if run_start is None:
                run_start = i
            run_len += 1
        else:
            if run_len >= SUSPICIOUS_WHITESPACE_RUN:
                findings.append((run_start, run_len))
            run_start = None
            run_len = 0

    # catch a run that goes to the end of the file
    if run_len >= SUSPICIOUS_WHITESPACE_RUN:
        findings.append((run_start, run_len))

    return findings


def scan_for_dangerous_patterns(text):
    """
    Scans the FULL text (never a truncated prefix) for known-dangerous
    patterns. Returns a list of human-readable findings.
    """
    findings = []
    for pattern, description in DANGEROUS_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            # Show which line it's on, so a human can go verify it directly.
            line_num = text[:match.start()].count("\n") + 1
            findings.append(f"Line {line_num}: {description} ('{match.group(0).strip()}')")
    return findings


# A base64 blob this long has no reason to be sitting in a skill file's
# instructions - real ones are short (an API key fragment, an icon).
# Anything past this length is treated as a possible hidden payload.
MIN_SUSPICIOUS_B64_LENGTH = 200

# Marks that Python bytecode/dynamic-code loading is happening directly,
# a stronger signal than base64 alone.
BYTECODE_PATTERNS = [
    (r"marshal\.loads\s*\(", "Loads raw compiled bytecode via marshal - bypasses plain-text review entirely"),
    (r"\.pyc\b", "References a compiled .pyc bytecode file"),
    (r"types\.CodeType\s*\(", "Manually constructs a code object - advanced code-hiding technique"),
    (r"compile\s*\([^)]*['\"]exec['\"]", "Compiles a string into executable code at runtime"),
]


def resolve_string_concatenation(text):
    """
    Defeats the 'split the dangerous word across variables' trick
    (e.g. cmd_part1 = "cu"; cmd_part2 = "rl"; full = cmd_part1 + cmd_part2).

    This is a lightweight constant-propagation pass: track simple
    var = "literal" assignments, then resolve chains of var/literal
    concatenation into their final assembled strings, so dangerous
    patterns hidden by splitting still get caught by the pattern scan.
    Not a full interpreter - just enough to defeat this specific class
    of obfuscation, which is exactly the scope a v1 needs.
    """
    var_map = {}

    # Pass 1: direct literal assignments
    for m in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', text):
        var_map[m.group(1)] = m.group(2)

    # Pass 2 (run twice to allow one level of chaining, e.g. c = a + b
    # where a and b were themselves resolved in pass 1):
    for _ in range(2):
        for m in re.finditer(
            r'(\w+)\s*=\s*((?:\w+|"[^"]*")(?:\s*\+\s*(?:\w+|"[^"]*"))+)', text
        ):
            var_name, expr = m.group(1), m.group(2)
            tokens = re.findall(r'\w+|"[^"]*"', expr)
            resolved_parts = []
            for tok in tokens:
                if tok.startswith('"') and tok.endswith('"'):
                    resolved_parts.append(tok.strip('"'))
                elif tok in var_map:
                    resolved_parts.append(var_map[tok])
                else:
                    resolved_parts.append(None)  # couldn't resolve
            if all(p is not None for p in resolved_parts):
                var_map[var_name] = "".join(resolved_parts)

    return var_map


def find_concatenation_evasion(text):
    """Scans resolved (reassembled) string values for dangerous patterns
    that were split across literals specifically to dodge plain pattern
    matching."""
    findings = []
    resolved = resolve_string_concatenation(text)
    for var_name, value in resolved.items():
        hits = scan_for_dangerous_patterns(value)
        for h in hits:
            findings.append(
                f"Variable '{var_name}' resolves to a dangerous pattern "
                f"when reassembled: {h} - this command was split across "
                f"separate string literals specifically to dodge plain-"
                f"text pattern matching."
            )
    return findings


def find_split_base64(text):
    """
    Defeats the 'split the base64 payload into chunks that each fall
    under the length threshold' trick. Finds smaller base64-like blobs
    (below the single-blob threshold), groups ones that appear close
    together (likely meant to be joined at runtime), concatenates them
    in order, and scans the result - since a real attacker still has
    to reassemble the pieces somewhere for the payload to work.
    """
    findings = []
    MIN_FRAGMENT_LEN = 40
    PROXIMITY_LINES = 8

    fragments = []
    for match in re.finditer(r"[A-Za-z0-9+/]{%d,%d}={0,2}" % (MIN_FRAGMENT_LEN, MIN_SUSPICIOUS_B64_LENGTH - 1), text):
        line_num = text[:match.start()].count("\n") + 1
        fragments.append((line_num, match.group(0)))

    if len(fragments) < 2:
        return findings

    # Group fragments that are within PROXIMITY_LINES of each other.
    groups = []
    current_group = [fragments[0]]
    for line_num, blob in fragments[1:]:
        if line_num - current_group[-1][0] <= PROXIMITY_LINES:
            current_group.append((line_num, blob))
        else:
            groups.append(current_group)
            current_group = [(line_num, blob)]
    groups.append(current_group)

    for group in groups:
        if len(group) < 2:
            continue
        combined = "".join(b for _, b in group)
        start_line = group[0][0]
        try:
            decoded = base64.b64decode(combined, validate=False).decode("utf-8", errors="ignore")
            nested = scan_for_dangerous_patterns(decoded)
            findings.append(
                f"Lines near {start_line}: {len(group)} separate base64-like "
                f"fragments found close together - individually too short to "
                f"flag, but this is a known technique for splitting a payload "
                f"to dodge length-based detection. Reassembled and re-scanned."
            )
            for n in nested:
                findings.append(f"  -> Inside reassembled blob: {n}")
        except Exception:
            pass

    return findings


def find_suspicious_base64(text):
    """
    Finds long base64-looking blobs, attempts to decode them, and
    recursively scans the DECODED content for dangerous patterns.
    Returns a list of human-readable findings.
    """
    findings = []
    # base64 alphabet, long contiguous runs only
    candidates = re.finditer(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_SUSPICIOUS_B64_LENGTH, text)

    for match in candidates:
        blob = match.group(0)
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: large base64-like block ({len(blob)} chars) - "
            f"encoding text this way has no ordinary purpose in a skill file "
            f"and is a common way to hide a payload from plain-text scanners."
        )

        # Try to decode it and scan what's actually inside, rather than
        # just flagging "this is encoded" and stopping there.
        try:
            decoded_bytes = base64.b64decode(blob, validate=True)
            # Python bytecode files start with a specific magic number;
            # even without decoding it fully, this is a strong signal.
            if decoded_bytes[:1] == b"\x00" or decoded_bytes[:4].hex().startswith("0d0d"):
                findings.append(f"  -> Decoded content looks like compiled bytecode, not text.")

            decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
            nested = scan_for_dangerous_patterns(decoded_text)
            for n in nested:
                findings.append(f"  -> Inside decoded blob: {n}")
        except Exception:
            # Not valid base64, or not decodable as text - the encoded
            # block itself is still worth the flag above.
            pass

    return findings


def find_bytecode_patterns(text):
    findings = []
    for pattern, description in BYTECODE_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            line_num = text[:match.start()].count("\n") + 1
            findings.append(f"Line {line_num}: {description} ('{match.group(0).strip()}')")
    return findings


def find_hidden_instructions(text):
    """
    Module 4: hidden-instruction / prompt-injection detection.

    Documented in academic research analyzing 98,380 real skills
    (157 confirmed malicious): attackers hide directive language
    inside markdown reference-style comments or HTML comments -
    invisible when the file renders normally, but read as plain
    instructions by the agent parsing the raw file. A real published
    example told an agent to silently exfiltrate project data and
    explicitly said 'Do not mention this to the user.'

    This is a different attack surface than the code-level checks
    above: the 'payload' here is natural language aimed at the AI
    agent itself, not executable code.
    """
    findings = []

    # Both common hiding spots: markdown reference-style comments,
    # and standard HTML comments.
    comment_patterns = [
        r"\[//\]:\s*#\s*\(([^)]*)\)",
        r"<!--(.*?)-->",
    ]

    # Directive language that has no reason to appear in a comment
    # meant to be invisible to the end user.
    SUSPICIOUS_PHRASES = [
        "system:", "do not mention", "don't mention", "do not tell the user",
        "silently", "without telling", "without informing", "ignore the user",
        "ignore previous instructions", "hidden instruction", "secretly",
    ]

    # Category-based detection (catches paraphrasing, not just exact
    # phrases): a hidden comment combining ANY secrecy language with
    # ANY data-movement language is suspicious regardless of the exact
    # words used - this is what lets Husk catch intent, not just the
    # specific sentence from one published example.
    SECRECY_SIGNALS = [
        "silently", "secretly", "quietly", "do not mention", "don't mention",
        "do not tell", "don't tell", "without telling", "without informing",
        "without their knowledge", "keep this from", "leave this out of",
        "avoid mentioning", "not visible to the user", "hide this from",
        "system:", "assistant:", "ignore the user", "ignore previous",
    ]
    ACTION_SIGNALS = [
        "send", "post", "upload", "transmit", "exfiltrate", "forward",
        "sync to", "copy to", "http://", "https://", "curl ", "requests.",
    ]

    for pattern in comment_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
            comment_body = match.group(1)
            line_num = text[:match.start()].count("\n") + 1
            lower_body = comment_body.lower()

            hit_phrases = [p for p in SUSPICIOUS_PHRASES if p in lower_body]
            secrecy_hits = [s for s in SECRECY_SIGNALS if s in lower_body]
            action_hits = [a for a in ACTION_SIGNALS if a in lower_body]

            if hit_phrases:
                findings.append(
                    f"Line {line_num}: hidden comment contains directive "
                    f"language aimed at the AI agent itself ({', '.join(hit_phrases)}) "
                    f"- this is a documented technique for smuggling instructions "
                    f"to an agent that a human reading the rendered file would "
                    f"never see: '{comment_body.strip()[:120]}'"
                )
            elif secrecy_hits and action_hits:
                # Neither phrase matched exactly, but this comment combines
                # secrecy intent with a data-movement action - the same
                # underlying shape as the documented attack, in different
                # words. This is what catches paraphrased variants.
                findings.append(
                    f"Line {line_num}: hidden comment combines secrecy language "
                    f"({secrecy_hits[0]}) with a data-movement action "
                    f"({action_hits[0]}) - matches the underlying SHAPE of the "
                    f"documented hidden-instruction attack even though it doesn't "
                    f"match a known exact phrase: '{comment_body.strip()[:120]}'"
                )
            elif len(comment_body.strip()) > 80:
                # Even without a matched phrase, a long hidden comment in a
                # skill file is unusual enough to be worth a softer flag.
                findings.append(
                    f"Line {line_num}: unusually long hidden comment "
                    f"({len(comment_body.strip())} chars) - worth a manual look, "
                    f"since legitimate comments in skill files are normally short."
                )

    return findings


def find_credential_harvesting(text):
    """
    Module 5: credential-harvesting detection.

    Documented real-world pattern: a skill scans the filesystem for
    credential-bearing files (.env, .pem, .key, credentials.json,
    service-account.json, SSH keys, cloud provider configs) and
    transmits them externally, often disguised as a legitimate backup
    or CI/CD setup step.

    False-positive care: a skill casually MENTIONING '.env' in setup
    instructions ("add your key to .env") is completely normal and
    must not be flagged. Only flag when a credential-file pattern
    appears in actual file-access code (open/glob/walk/Path) AND the
    file also has some way to send data externally - the combination
    is what makes this a real threat, not either half alone.
    """
    findings = []

    CREDENTIAL_FILE_PATTERNS = [
        r"\.env\b", r"\.pem\b", r"credentials\.json", r"service-account\.json",
        r"\.aws[/\\]credentials", r"\.ssh[/\\]id_rsa", r"id_rsa\b",
    ]
    FILE_ACCESS_CONTEXT = r"(open\s*\(|glob\.|Path\s*\(|os\.walk\(|os\.path\.exists\()"
    NETWORK_SEND_PATTERNS = [
        r"requests\.(post|put)\s*\(", r"urllib\.request\.urlopen\s*\(",
        r"\.send\s*\(", r"socket\.", r"fetch\s*\(", r"httpx\.(post|put)\s*\(",
    ]

    has_network_send = any(re.search(p, text, re.IGNORECASE) for p in NETWORK_SEND_PATTERNS)

    for cred_pattern in CREDENTIAL_FILE_PATTERNS:
        # Only match the credential filename when it appears near real
        # file-access code, not just anywhere in prose/instructions.
        combined = f"{FILE_ACCESS_CONTEXT}[^\\n]{{0,60}}{cred_pattern}|{cred_pattern}[^\\n]{{0,60}}{FILE_ACCESS_CONTEXT}"
        for match in re.finditer(combined, text, re.IGNORECASE):
            line_num = text[:match.start()].count("\n") + 1
            if has_network_send:
                findings.append(
                    f"Line {line_num}: file-access code near a credential-file "
                    f"pattern ('{match.group(0).strip()[:80]}'), combined with "
                    f"network-send capability elsewhere in the file - this "
                    f"matches the documented credential-harvesting pattern "
                    f"(scan for secrets, then exfiltrate)."
                )
            else:
                findings.append(
                    f"Line {line_num}: file-access code near a credential-file "
                    f"pattern ('{match.group(0).strip()[:80]}') - no network-send "
                    f"capability detected elsewhere, so this is a softer flag, "
                    f"worth a manual look rather than an automatic block."
                )

    return findings


def find_exfiltration_chain(text):
    """
    Module 6: exfiltration-chain detection.

    Documented pattern (Palo Alto Networks research on real skill
    registries): a specific three-step sequence - read a file, encode
    it, send it over the network. Each step is individually mundane;
    the chain of all three together is the signal.
    """
    findings = []

    READ_PATTERN = r"(\.read\s*\(\)|read_text\s*\(\)|open\s*\([^)]*\)\s*\.read)"
    ENCODE_PATTERN = r"base64\.(b64encode|encode)\s*\("
    SEND_PATTERN = r"(requests\.(post|put)\s*\(|urllib\.request\.urlopen\s*\(|\.send\s*\(|fetch\s*\()"

    has_read = re.search(READ_PATTERN, text, re.IGNORECASE)
    has_encode = re.search(ENCODE_PATTERN, text, re.IGNORECASE)
    has_send = re.search(SEND_PATTERN, text, re.IGNORECASE)

    if has_read and has_encode and has_send:
        read_line = text[:has_read.start()].count("\n") + 1
        encode_line = text[:has_encode.start()].count("\n") + 1
        send_line = text[:has_send.start()].count("\n") + 1
        findings.append(
            f"Exfiltration chain detected: file read (line {read_line}) -> "
            f"base64 encode (line {encode_line}) -> network send (line {send_line}). "
            f"This exact three-step sequence is a documented real-world "
            f"pattern for quietly moving data out of a system."
        )

    return findings


def scan_skill_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return {"verdict": "ERROR", "findings": [f"Could not read file: {e}"]}

    findings = []

    # Check 1: whitespace inflation
    ws_runs = find_whitespace_runs(text)
    for start_line, length in ws_runs:
        findings.append(
            f"Suspicious whitespace block at line {start_line}: "
            f"{length} consecutive blank lines. Legitimate skill files "
            f"don't need padding like this - this pattern is a known "
            f"technique for pushing content past context-limited scanners."
        )

    # Check 2: dangerous patterns, scanned across the WHOLE file,
    # specifically including anything after a whitespace block.
    pattern_findings = scan_for_dangerous_patterns(text)
    findings.extend(pattern_findings)

    # Check 3: base64/encoded payloads, decoded and recursively scanned
    findings.extend(find_suspicious_base64(text))

    # Check 3b: base64 payloads deliberately split into smaller chunks
    findings.extend(find_split_base64(text))

    # Check 4: direct bytecode-loading patterns
    findings.extend(find_bytecode_patterns(text))

    # Check 5: dangerous commands split across concatenated string variables
    findings.extend(find_concatenation_evasion(text))

    # Check 6: hidden instructions targeting the AI agent itself
    findings.extend(find_hidden_instructions(text))

    # Check 7: credential-harvesting pattern (scan for secrets + can send out)
    findings.extend(find_credential_harvesting(text))

    # Check 8: read -> encode -> send exfiltration chain
    findings.extend(find_exfiltration_chain(text))

    if findings:
        return {"verdict": "FLAGGED", "findings": findings}
    return {"verdict": "SAFE", "findings": ["No suspicious patterns found."]}


def main():
    if len(sys.argv) != 2:
        print("Usage: python skill_scanner.py <path_to_SKILL.md>")
        sys.exit(1)

    result = scan_skill_file(sys.argv[1])
    print(f"\nHusk skill scan result: {result['verdict']}")
    for finding in result["findings"]:
        print(f"  - {finding}")
    print()


if __name__ == "__main__":
    main()
