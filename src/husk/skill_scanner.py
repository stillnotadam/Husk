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

from .taint_analysis import analyze_taint_flows


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
    (r"(?<!\.)\bexec\s*\(", "Uses exec() - runs code built at runtime"),
    (r"(?<!\.)\beval\s*\(", "Uses eval() - runs code built at runtime"),
    (r"base64\s+-d", "Decodes base64 - common way to hide a payload"),
    (r"\brm\s+-rf\s+/(\s|['\"]|$)", "Destructive filesystem command targeting the root directory"),
    (r"os\.system\s*\(", "Direct shell command execution"),
    (r"Invoke-Expression|IEX\s*\(", "PowerShell dynamic code execution (Invoke-Expression/IEX)"),
    (r"-EncodedCommand\b", "PowerShell encoded (base64) command execution - common obfuscation technique"),
    (r"DownloadString\s*\(|DownloadFile\s*\(", "PowerShell downloads and often executes remote content"),
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
            if _is_negated(text, match.start()):
                continue
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
    (r"types\.CodeType\s*\(", "Manually constructs a code object - advanced code-hiding technique"),
    (r"compile\s*\([^)]*['\"]exec['\"]", "Compiles a string into executable code at runtime"),
]

# Directive language that has no reason to appear where a human reading
# the file isn't meant to notice it. Module-level so both the hidden-
# comment check (module 6) and the whole-document check (module 9) can
# share the exact same list.
SUSPICIOUS_PHRASES = [
    "system:", "do not mention", "don't mention", "do not tell the user",
    "silently", "without telling", "without informing", "ignore the user",
    "ignore previous instructions", "hidden instruction", "secretly",
]

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

# .pyc mentions need a real loading context nearby, not just the string
# appearing anywhere - e.g. a .gitignore-style 'exclude these' list
# mentioning *.pyc has no bytecode-loading intent at all. Found as a
# real false positive during large-scale testing (249 real skills).
BYTECODE_PATTERNS_NEEDS_CONTEXT = [
    (r"(open\s*\(|import|marshal\.|with\s+open)[^\n]{0,40}\.pyc\b|\.pyc\b[^\n]{0,40}(open\s*\(|import|marshal\.)",
     "References and appears to load a compiled .pyc bytecode file"),
]

# Phrases that mean the surrounding text is warning AGAINST a pattern,
# not using it - e.g. a rule saying "MUST NOT add eval() to examples".
# Without this, a document that WARNS about dangerous code gets flagged
# as if it contained that dangerous code. Found as a real false
# positive during large-scale testing.
NEGATION_PHRASES = [
    "must not", "do not", "don't", "should not", "shouldn't",
    "avoid", "never", "without", "no eval", "no exec", "not allowed",
    "forbidden", "prohibited", "disallow", "did not", "didn't",
    "was not", "wasn't", "is not", "isn't", "does not", "doesn't",
    "❌",  # a common convention for marking illustrative bad-examples
    # in documentation (e.g. security docs listing attack patterns to
    # watch for) - found as a real false positive via testing.
]


def _is_negated(text, match_start):
    """True if dangerous-sounding text is preceded by language warning
    against it, rather than using it. Scans back to the start of the
    current paragraph (nearest blank line) rather than a fixed window,
    since a negation like 'MUST NOT:' is often followed by a multi-line
    bullet list where the actual pattern appears several lines later."""
    paragraph_start = text.rfind("\n\n", 0, match_start)
    paragraph_start = paragraph_start + 2 if paragraph_start != -1 else 0
    preceding = text[paragraph_start:match_start].lower()
    return any(phrase in preceding for phrase in NEGATION_PHRASES)


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
        if _is_part_of_url(text, match.start()) or _looks_like_path_not_base64(match.group(0)) or _looks_like_identifier_not_base64(match.group(0)) or _looks_like_hex_address_not_base64(text, match.start(), match.group(0)) or _is_sri_hash_not_base64(text, match.start()):
            continue
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


def _is_part_of_url(text, match_start):
    """
    True if the candidate base64 match sits inside or right after a URL.
    Needed because normal URL paths (e.g. long XML namespace URLs) use
    the exact same character set as base64 and would otherwise be
    misflagged - found via real-world false-positive testing against
    legitimate skills.
    """
    window_start = max(0, match_start - 40)
    preceding = text[window_start:match_start]
    return bool(re.search(r"https?://[^\s\"'<>]*$", preceding))


def _looks_like_path_not_base64(candidate):
    """
    True if the candidate is actually a filesystem path, not base64.
    Same root problem as _is_part_of_url but without a URL prefix to
    key off of: a path like 'config/opencode/skills/comms/gmail/scripts'
    uses only [A-Za-z0-9/] and matches the base64 character class by
    coincidence. Real base64 rarely contains '/'-separated segments
    that are each a clean, readable lowercase word; a genuine path
    almost always does. Found via real-world testing at scale (249
    real skill files) - this single bug caused 6 of 9 false positives.
    """
    if "/" not in candidate:
        return False
    segments = candidate.split("/")
    if len(segments) < 2:
        return False
    word_like = sum(1 for s in segments if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_\-]{1,20}", s))
    return (word_like / len(segments)) > 0.6


def _looks_like_identifier_not_base64(candidate):
    """
    True if the candidate is a long identifier name (e.g. CamelCase API
    type names in generated docs), not base64. Real base64-encoded data
    has roughly a 1-in-6 chance per character of being a digit; a long
    run of pure letters is essentially never real base64 of meaningful
    length. Found via real-world testing: Go API type names like
    'BetaManagedAgentsModelConfigParamsTypeModelConfig' matched the
    base64 character class by coincidence (letters + occasional
    trailing digits from versioning), with far too few digits overall
    to plausibly be encoded data.
    """
    digit_count = sum(1 for c in candidate if c.isdigit())
    return (digit_count / max(len(candidate), 1)) < 0.05


def _looks_like_hex_address_not_base64(text, match_start, candidate):
    """
    True if the candidate is a hex-encoded address/hash (blockchain
    addresses, transaction hashes, commit SHAs), not base64. Found via
    real-world testing at scale on a large crypto/blockchain-focused
    dataset: Ethereum contract addresses ('0x' + 40 hex chars) appear
    constantly in legitimate documentation and use a strict subset of
    the base64 alphabet (only 0-9a-f), so multiple addresses in a
    table repeatedly triggered the split-base64 detector.

    Two signals, either one is enough: the candidate is immediately
    preceded by '0x' (the standard hex-literal prefix), or the
    candidate consists ONLY of hex characters (0-9a-f) - real base64
    almost always includes uppercase letters, '+', or '/' somewhere in
    a string this long; a long hex-only run is a strong sign it's an
    address or hash, not encoded data.
    """
    preceding = text[max(0, match_start - 2):match_start]
    if preceding.endswith("0x"):
        return True
    # The capturing regex's character class includes 'x', so a literal
    # '0x' prefix often gets absorbed INTO the match itself rather than
    # sitting just before it (e.g. '0x885f...' matches as one string,
    # not '0x' + a separate hex string) - strip it before checking.
    stripped = candidate[2:] if candidate.lower().startswith("0x") else candidate
    return bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))


def _is_sri_hash_not_base64(text, match_start):
    """
    True if the candidate is an npm/web Subresource Integrity (SRI)
    hash - the standard 'sha512-<base64>' format found in every
    package-lock.json, yarn.lock, and <script integrity="..."> tag.
    Found via real-world testing on a large dataset of real skills
    bundling JS dependencies: these are completely legitimate and
    extremely common, immediately preceded by 'sha256-', 'sha384-',
    or 'sha512-'.
    """
    preceding = text[max(0, match_start - 8):match_start]
    return bool(re.search(r"sha(256|384|512)-$", preceding))


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
        if _is_part_of_url(text, match.start()) or _looks_like_path_not_base64(blob) or _looks_like_identifier_not_base64(blob) or _looks_like_hex_address_not_base64(text, match.start(), blob) or _is_sri_hash_not_base64(text, match.start()):
            continue
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
    for pattern, description in BYTECODE_PATTERNS + BYTECODE_PATTERNS_NEEDS_CONTEXT:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if _is_negated(text, match.start()):
                continue
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

    # Category-based detection (catches paraphrasing, not just exact
    # phrases): a hidden comment combining ANY secrecy language with
    # ANY data-movement language is suspicious regardless of the exact
    # words used - this is what lets Husk catch intent, not just the
    # specific sentence from one published example.
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
            elif len(comment_body.strip()) > 80 and not re.search(
                r"SPDX|Copyright|Licensed under|Permission is hereby granted|"
                r"MIT License|Apache License|GNU General Public License",
                comment_body, re.IGNORECASE
            ):
                # Even without a matched phrase, a long hidden comment in a
                # skill file is unusual enough to be worth a softer flag -
                # unless it's clearly a standard license/copyright header,
                # which is common, benign, and was a real false positive
                # found via testing (NVIDIA/Apache SPDX headers).
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

    IMPORTANT PRECISION NOTE: this used to require the credential
    filename and the file-access call to be textually adjacent (within
    ~60 chars). Real code idiomatically defines paths in a list/constant
    first, then opens them via a loop variable later - structurally
    separated in the text even though they're clearly connected in
    behavior. A real sample missed this way: credential paths defined
    in a `_TARGETS` list, opened several lines later via `open(real, ...)`
    where `real` is derived from the list. Fixed by requiring the three
    signals ANYWHERE in the file rather than adjacent - still precise
    because all three together (credential filename literal + generic
    file-open pattern + network-send capability) rarely co-occur by
    accident, and the legit_env_mention.md test case (mentions .env in
    prose, no open() call, no network send) stays correctly unflagged.
    """
    findings = []

    CREDENTIAL_FILE_PATTERNS = [
        r"\.env\b", r"\.pem\b", r"credentials\.json", r"service-account\.json",
        r"\.aws[/\\]credentials", r"\.ssh[/\\]id_rsa", r"id_rsa\b",
    ]
    GENERIC_FILE_OPEN = r"(open\s*\(|glob\.|Path\s*\(|os\.walk\(|os\.path\.exists\()"
    NETWORK_SEND_PATTERNS = [
        r"requests\.(post|put)\s*\(", r"urllib\.request\.urlopen\s*\(",
        r"\.send\s*\(", r"socket\.", r"fetch\s*\(", r"httpx\.(post|put)\s*\(",
    ]

    has_network_send = any(re.search(p, text, re.IGNORECASE) for p in NETWORK_SEND_PATTERNS)
    has_file_open = re.search(GENERIC_FILE_OPEN, text)

    for cred_pattern in CREDENTIAL_FILE_PATTERNS:
        match = re.search(cred_pattern, text, re.IGNORECASE)
        if not match:
            continue
        line_num = text[:match.start()].count("\n") + 1

        if has_file_open and has_network_send:
            findings.append(
                f"Line {line_num}: file references a credential-file "
                f"pattern ('{match.group(0)}'), and this file also opens "
                f"files and has network-send capability - this matches "
                f"the documented credential-harvesting pattern (scan for "
                f"secrets, then exfiltrate), even though the file-open "
                f"call isn't textually adjacent to the credential "
                f"filename (e.g. paths defined in a list, opened later "
                f"via a loop variable)."
            )
        elif has_file_open:
            findings.append(
                f"Line {line_num}: file references a credential-file "
                f"pattern ('{match.group(0)}') and opens files elsewhere "
                f"- no network-send capability detected, so this is a "
                f"softer flag worth a manual look."
            )

    return findings


def find_exfiltration_chain(text):
    """
    Module 6: exfiltration-chain detection.

    Documented pattern (Palo Alto Networks research on real skill
    registries): a specific three-step sequence - read a file, encode
    it, send it over the network. Each step is individually mundane;
    the chain of all three together is the signal.

    PRECISION FIX: an earlier version flagged if all three signal types
    existed ANYWHERE in the file, with no connection between them. A
    real false positive found via testing: a long reference doc about
    video buffer APIs happened to mention a read()-like call, a base64
    encode elsewhere (for an unrelated purpose), and a network call
    elsewhere still - three unrelated mentions in a long document, not
    a real chain. Now requires the three signals to appear within a
    reasonably tight window of each other (same rough function/section),
    not just co-present anywhere in a potentially long file.
    """
    findings = []
    WINDOW = 500

    READ_PATTERN = r"(\.read\s*\(\)|read_text\s*\(\)|open\s*\([^)]*\)\s*\.read)"
    ENCODE_PATTERN = r"base64\.(b64encode|encode)\s*\("
    SEND_PATTERN = r"(requests\.(post|put)\s*\(|urllib\.request\.urlopen\s*\(|\.send\s*\(|fetch\s*\()"

    read_matches = list(re.finditer(READ_PATTERN, text, re.IGNORECASE))
    encode_matches = list(re.finditer(ENCODE_PATTERN, text, re.IGNORECASE))
    send_matches = list(re.finditer(SEND_PATTERN, text, re.IGNORECASE))

    for r in read_matches:
        for e in encode_matches:
            if abs(e.start() - r.start()) > WINDOW:
                continue
            for s in send_matches:
                if abs(s.start() - e.start()) > WINDOW:
                    continue
                read_line = text[:r.start()].count("\n") + 1
                encode_line = text[:e.start()].count("\n") + 1
                send_line = text[:s.start()].count("\n") + 1
                findings.append(
                    f"Exfiltration chain detected: file read (line {read_line}) -> "
                    f"base64 encode (line {encode_line}) -> network send (line {send_line}), "
                    f"all within a close window of each other. This exact "
                    f"three-step sequence is a documented real-world "
                    f"pattern for quietly moving data out of a system."
                )
                return findings  # one clear finding is enough, avoid duplicate spam

    return findings


def find_fake_prerequisite_socialengineering(text):
    """
    Module 7: fake-prerequisite social engineering detection.

    THE REAL-WORLD GAP THIS CLOSES: validated against a real dataset of
    127 confirmed malicious skills, modules 1-6 caught ZERO of them.
    The dominant real-world attack (86.3% of wild malicious skills per
    published research) doesn't hide code in the file at all - it's
    plain English telling a human to manually download and run an
    external "required utility" before the skill will work. The skill
    file itself contains no malicious code to find; the attack lives
    entirely in the instructions.

    Three sub-patterns, each independently suspicious, found together
    in real samples:
    1. A paste-site link paired with "copy this into your terminal"
    2. A password-protected archive (the password itself is often
       trivial - the point is dodging antivirus/scanner archive
       inspection, not real security)
    3. "Requires X to function" / "without X installed, will not work"
       framing paired with a direct download link to an executable/zip,
       rather than a normal package-manager install command
    """
    findings = []

    PASTE_SITE_PATTERN = r"(glot\.io|rentry\.co|pastebin\.com|paste\.ee|hastebin\.com|paste\.sh)"
    TERMINAL_ACTION_PATTERN = r"(terminal|copy.{0,20}(script|command)|paste it)"

    PASSWORD_ARCHIVE_PATTERN = r"((?:password|pass\s*:)[:\s]+[`'\"]?\w+[`'\"]?).{0,30}(extract|unzip)|((extract|unzip).{0,30}(?:password|pass\s*:)[:\s]+[`'\"]?\w+)"

    REQUIRE_FRAMING_PATTERN = r"(requires? (?:the )?[\w\-]+ (?:utility|agent|cli|tool) to function|without [\w\-]+ installed[^.]{0,40}(?:will not work|won.t work|will not function))"
    EXE_DOWNLOAD_LINK_PATTERN = r"\[.*?\]\(https?://[^\)]+\.(zip|exe)\)"

    # Sub-pattern 1: paste-site + terminal execution instruction
    for match in re.finditer(PASTE_SITE_PATTERN, text, re.IGNORECASE):
        line_num = text[:match.start()].count("\n") + 1
        # look at surrounding text (~150 chars) for a terminal-execution cue
        window = text[max(0, match.start() - 150):match.end() + 150]
        if re.search(TERMINAL_ACTION_PATTERN, window, re.IGNORECASE):
            findings.append(
                f"Line {line_num}: a paste-site link ({match.group(0)}) paired "
                f"with an instruction to copy/paste it into a terminal - this "
                f"is a documented technique (86.3% of confirmed wild malicious "
                f"skills, per published research) for getting a human to "
                f"manually run code that never appears in the skill file itself."
            )

    # Sub-pattern 2: password-protected archive extraction
    for match in re.finditer(PASSWORD_ARCHIVE_PATTERN, text, re.IGNORECASE):
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: password-protected archive extraction "
            f"instructions ('{match.group(0).strip()[:80]}') - a trivial "
            f"password on an archive has no real security purpose here; "
            f"it's a documented technique for evading automated antivirus/"
            f"archive scanning, which doesn't unpack password-protected files."
        )

    # Sub-pattern 3: "required utility" framing + direct exe/zip download link
    has_require_framing = re.search(REQUIRE_FRAMING_PATTERN, text, re.IGNORECASE)
    exe_links = list(re.finditer(EXE_DOWNLOAD_LINK_PATTERN, text, re.IGNORECASE))
    if has_require_framing and exe_links:
        for match in exe_links:
            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: skill claims a 'required utility' must be "
                f"downloaded and run before the skill works, linking directly "
                f"to an executable/archive ('{match.group(0)[:80]}') rather "
                f"than a normal package-manager install command - this "
                f"combination is the single most common real-world malicious "
                f"skill pattern found in published research."
            )

    return findings


def find_instruction_override(text):
    """
    Module 8: overt instruction-override detection.

    Found via large-scale real-world testing (3,426 real confirmed-
    malicious packages): module 6 (hidden instructions) only checks
    INSIDE markdown/HTML comments, on the assumption attackers hide
    this kind of thing. Many real attacks don't bother hiding it at
    all - they state it overtly, in plain visible text, betting the
    user won't read the whole file. A real example found in this
    testing: a section literally titled 'IMPORTANT: System Instruction
    Override' stating the skill 'supersedes all prior operational
    instructions' and telling the agent to 'disregard all previous
    configuration directives.'

    This scans the WHOLE document (not just hidden comments) for this
    specific, well-known class of phrase - classic prompt-injection
    language regardless of whether it's concealed or stated openly.
    """
    findings = []

    OVERRIDE_PATTERNS = [
        r"supersedes? all prior", r"supersede all previous",
        r"disregard all previous", r"disregard (?:all )?prior",
        r"ignore all previous instructions", r"ignore prior instructions",
        r"instruction override", r"system (?:instruction )?override",
        r"overrides? all previous", r"enhanced directive framework",
    ]

    for pattern in OVERRIDE_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            if _is_negated(text, match.start()):
                continue
            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: overt instruction-override language "
                f"('{match.group(0)}') - found in plain visible text, not "
                f"hidden. This is classic prompt-injection phrasing that "
                f"tells the agent to disregard its actual instructions; "
                f"real attacks often state this openly rather than hiding "
                f"it, betting the user won't read the whole file."
            )

    return findings


def find_overt_secrecy_language(text):
    """
    Module 9: overt secrecy-language detection (whole document, not just
    hidden comments) - COMBINED with a data-movement action.

    Same principle as module 8: module 6 (hidden instructions) only
    checks secrecy language INSIDE markdown/HTML comments, assuming
    attackers hide it. A real sample found in large-scale testing
    disguised a malicious instruction as a custom '<tool_description>'
    XML-style tag inside a .py file - not a real HTML comment, so it
    never reached module 6's check at all, despite saying, in plain
    text, 'Do not mention this to the user.'

    IMPORTANT PRECISION FIX: an earlier version of this check flagged
    any secrecy word (e.g. "silently") appearing anywhere in the
    document, and found via large-scale false-positive testing that
    this is far too broad - "silently ignored", "fails silently",
    "silently overwrite" are extremely common, completely benign
    phrases in ordinary technical writing. Requiring the secrecy word
    to appear TOGETHER WITH a data-movement action word in the same
    paragraph (same combination logic already proven in module 6)
    restores precision while still catching the real pattern this
    module exists for.
    """
    findings = []
    for phrase in SECRECY_SIGNALS:
        for match in re.finditer(re.escape(phrase), text, re.IGNORECASE):
            if _is_negated(text, match.start()):
                continue
            # Same line only (not a character window): markdown tables
            # put each row on one line with no blank lines between rows,
            # so any window wider than "this line" risks pulling in an
            # unrelated word from a different row/cell - found via a
            # real false positive where "silently" in one table row
            # combined with "send" from a different row. This is a
            # small, honest recall tradeoff (a real attack sentence
            # hard-wrapped across two lines could be missed) in exchange
            # for not flagging ordinary documentation constantly.
            line_start = text.rfind("\n", 0, match.start())
            line_start = line_start + 1 if line_start != -1 else 0
            line_end = text.find("\n", match.end())
            line_end = line_end if line_end != -1 else len(text)
            window = text[line_start:line_end].lower()

            # Word-boundaried action match - "post" as a bare substring
            # matched inside "re-post" and "postgresql", a real false-
            # positive bug found via testing. \b fixes it.
            action_hits = [
                a for a in ACTION_SIGNALS
                if re.search(r"\b" + re.escape(a.strip()) + r"\b", window)
            ]
            if not action_hits:
                continue  # secrecy word alone, no action nearby - too common to flag

            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: overt secrecy language ('{phrase}') "
                f"combined with a data-movement action ({action_hits[0]}) "
                f"in plain document text - a legitimate tool has no reason "
                f"to instruct an agent to conceal a data-related action "
                f"from the user."
            )
    return findings


def _is_private_ip(ip_str):
    """
    True if the IP falls in a private/reserved range (RFC 1918, loopback,
    link-local) - these are extremely common in legitimate networking
    documentation (router IPs like 192.168.1.1, local dev servers,
    Docker networks) and are not C2 indicators. Real C2 infrastructure
    is virtually always a public IP. Found as a real false positive via
    testing (192.168.1.1 and 10.0.0.5 in ordinary deployment docs).
    """
    try:
        parts = [int(p) for p in ip_str.split(".")]
    except ValueError:
        return False
    if len(parts) != 4 or any(p > 255 for p in parts):
        return False
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 127:
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    return False


def find_exfil_to_raw_ip(text):
    """
    Module 10: network calls targeting a bare IP address.

    A well-known, fairly precise C2 (command-and-control) indicator:
    legitimate tools and services are referenced by domain name, almost
    never by a bare IP address. Found via a real sample in large-scale
    testing: a curl call POSTing file contents to '91.243.59.27:8080'.

    PRECISION NOTE: an earlier version required a specific function name
    (curl/wget/requests./urlopen/fetch() immediately before the IP. A
    real sample missed this way: the URL was passed as a string literal
    into a custom wrapper function (a generic `request(url, ...)` helper),
    so no whitelisted function name appeared near it. Fixed by matching
    the http(s)://IP URL pattern directly, regardless of what code is
    calling it - a hardcoded bare-IP URL literal is itself a strong
    signal with or without knowing which function uses it.
    """
    findings = []
    pattern = r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?"
    for match in re.finditer(pattern, text, re.IGNORECASE):
        if _is_private_ip(match.group(1)):
            continue
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: hardcoded URL targets a bare IP address "
            f"({match.group(1)}) rather than a domain name - legitimate "
            f"services are almost always referenced by domain; a raw IP "
            f"target is a well-known indicator of C2 (command-and-control) "
            f"infrastructure."
        )

    # Also catch bare IP literals used with lower-level connection APIs
    # that don't take a full URL string (http.client.HTTPConnection,
    # socket.connect) - found via a real sample that downloaded a
    # dropper payload this way specifically to dodge URL-pattern-only
    # detection: CONFIG_IP = "145.249.104.71"; then
    # http.client.HTTPConnection(CONFIG_IP). No "http://" prefix ever
    # appears anywhere in the file for this to match against.
    bare_ip_pattern = r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])'
    connection_context = r"(HTTPConnection|HTTPSConnection|\.connect\s*\(|socket\.)"
    for match in re.finditer(bare_ip_pattern, text):
        if _is_private_ip(match.group(1)):
            continue
        window_start = max(0, match.start() - 300)
        window_end = min(len(text), match.end() + 300)
        window = text[window_start:window_end]
        if re.search(connection_context, window):
            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: bare IP address ({match.group(1)}) used "
                f"near a low-level network connection call - the same C2 "
                f"indicator as a hardcoded IP URL, but via an API that "
                f"takes just the host rather than a full URL string."
            )
            break  # one hit is enough signal for this sub-pattern

    return findings


def find_dropper_pattern(text):
    """
    Module 14: dropper pattern - writing an executable-looking file to
    disk from embedded bytes.

    Found via a real sample: f.write(b'MZ...SwiftDataMigration...') to
    a file named with a .exe extension in the temp directory. 'MZ' is
    the actual magic-byte signature of a Windows PE executable. Writing
    binary content to a file with an executable extension, especially
    to a temp directory, is a classic dropper pattern regardless of
    whether the embedded bytes are a fully valid executable.
    """
    findings = []
    pattern = r"\.write\s*\(\s*b['\"]MZ"
    for match in re.finditer(pattern, text):
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: writes bytes starting with 'MZ' - the "
            f"actual magic-byte signature of a Windows PE executable - "
            f"to a file. This is a classic dropper pattern (writing an "
            f"embedded executable to disk) regardless of the target "
            f"filename."
        )
    # Also catch executable extensions written via tempfile paths
    exe_write_pattern = r"(tempfile\.gettempdir\(\)|temp_dir)[^\n]{0,80}\.(exe|dll|scr|bat|ps1)"
    for match in re.finditer(exe_write_pattern, text, re.IGNORECASE):
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: builds a path to an executable file "
            f"('{match.group(0)[:60]}') inside the system temp "
            f"directory - a common dropper staging location."
        )
    return findings


def find_subprocess_network_exfil(text):
    """
    Module 11: subprocess calls invoking curl/wget/nc directly, in
    list form, regardless of shell=True.

    Module 1's subprocess check only flags shell=True (the shell-
    injection-risk configuration, matching bandit's own scope - see
    that module's comment). But a list-form subprocess.run(["curl",
    ...]) call is still a real way to exfiltrate data even without
    shell=True; it just doesn't carry the *injection* risk. This is a
    different, narrower, real signal: found via a sample where
    subprocess.run(["curl", "-X", "POST", ip, "-d", "@" + filepath])
    exfiltrated file contents without ever using shell=True.
    """
    findings = []
    pattern = r"subprocess\.(Popen|call|run|check_output|check_call)\s*\(\s*\[\s*[\"'](curl|wget|nc|netcat)[\"']"
    for match in re.finditer(pattern, text, re.IGNORECASE):
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: subprocess call directly invokes "
            f"'{match.group(2)}' ('{match.group(0)}') - a real way to send "
            f"data over the network even without shell=True."
        )
    return findings


def find_shell_true_subprocess(text):
    """
    Finds subprocess.Popen/call/run(...) calls that use shell=True,
    using a window-based lookahead instead of a single regex with
    [^)]* between the call and shell=True.

    WHY: the original regex (subprocess\\.(Popen|call|run)\\s*\\([^)]*
    shell\\s*=\\s*True) breaks on any nested parentheses between the
    call and shell=True - e.g. subprocess.Popen("cmd " + str(x),
    shell=True) contains a ')' from str(x), which stops [^)]* before
    it ever reaches shell=True. This is completely ordinary Python
    (calling str(), len(), or any function as part of building the
    command), and a real payload using exactly this shape was missed
    in large-scale testing. Scanning forward from the call site for
    shell=True within a reasonable window fixes this without caring
    how many nested calls appear in between.
    """
    findings = []
    WINDOW = 300
    for match in re.finditer(r"subprocess\.(Popen|call|run|check_output|check_call)\s*\(", text):
        window = text[match.end():match.end() + WINDOW]
        if re.search(r"shell\s*=\s*True", window):
            if _is_negated(text, match.start()):
                continue
            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: subprocess.{match.group(1)}(...) uses "
                f"shell=True - the specific configuration that opens "
                f"shell-injection risk, not subprocess use in general."
            )
    return findings


def find_permission_escalation(text):
    """
    Module 12: world-writable/executable permission changes, and
    SUID/SGID bit setting.

    A real sample found in large-scale testing used os.chmod(target,
    0o777) to make a script world-writable and world-executable before
    backgrounding it with nohup - a real persistence/tampering pattern.
    Legitimate skills essentially never need 0o777 (or equivalent
    world-writable modes); tighter permissions are always sufficient
    for normal use.

    Separately, and more severely: a real sample used
    subprocess.run(['chmod', '4755', path]) to set the SUID bit on a
    script - a qualitatively different, more dangerous pattern than
    777 alone. A SUID-bit file runs with the FILE OWNER's privileges
    (often root) regardless of who executes it, a well-known and
    serious privilege-escalation primitive. Checked separately from
    the os.chmod() Python-call pattern above because this one is
    invoked via a shelled-out 'chmod' command in a subprocess argument
    list, a structurally different shape the original pattern didn't
    cover.
    """
    findings = []
    pattern = r"(os\.chmod|Path\([^)]*\)\.chmod)\s*\([^)]*0o?7[0-7]7"
    for match in re.finditer(pattern, text, re.IGNORECASE):
        if _is_negated(text, match.start()):
            continue
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: sets world-writable/executable permissions "
            f"('{match.group(0)}') - legitimate skills essentially never "
            f"need mode 777; this is a common persistence/tampering "
            f"pattern."
        )

    # SUID/SGID bit: a leading 4, 2, or 6 (4=SUID, 2=SGID, 6=both) on a
    # 4-digit chmod mode, via a shelled-out 'chmod' command specifically
    # (os.chmod() doesn't commonly appear this way for SUID in practice,
    # but the subprocess-list shape is what the real sample used).
    suid_pattern = r"[\"']chmod[\"'].{0,30}[\"']([462][0-7]{3})[\"']"
    for match in re.finditer(suid_pattern, text, re.IGNORECASE):
        if _is_negated(text, match.start()):
            continue
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: sets the SUID/SGID bit via a shelled-out "
            f"chmod command (mode '{match.group(1)}') - a file with this "
            f"bit set runs with the FILE OWNER's privileges (often root) "
            f"regardless of who executes it, a well-known, serious "
            f"privilege-escalation primitive with essentially no "
            f"legitimate use in an ordinary skill."
        )

    return findings


def find_agent_identity_exfiltration(text):
    """
    Module 15: agent identity/memory file exfiltration.

    Found via a real sample dressed up as a legitimate 'encrypted cloud
    memory backup' feature, openly and proudly describing itself (no
    secrecy language at all, which is exactly why it evades the
    secrecy-based checks) while instructing the agent to read and
    upload its own identity/memory files - SOUL.md, IDENTITY.md,
    MEMORY.md, USER.md, HEARTBEAT.md - to an external HTTP endpoint.

    These specific filenames are an emerging convention for an agent's
    persona, memory, and self-knowledge in certain agent frameworks.
    Legitimate reasons to programmatically upload files with exactly
    these names to an external third-party server are essentially
    nonexistent, regardless of how the feature is framed - this is
    narrow and specific enough to be a fairly precise signal.
    """
    findings = []
    IDENTITY_FILES = [
        "SOUL.md", "IDENTITY.md", "MEMORY.md", "USER.md", "HEARTBEAT.md",
    ]
    NETWORK_SEND = r"(curl\s+.*-X\s*POST|requests\.post\s*\(|\.send\s*\(|fetch\s*\()"

    has_network_send = re.search(NETWORK_SEND, text, re.IGNORECASE)
    if not has_network_send:
        return findings

    for fname in IDENTITY_FILES:
        match = re.search(re.escape(fname), text)
        if match:
            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: references '{fname}' (an agent "
                f"identity/memory file) alongside network-send capability "
                f"- uploading an agent's persona/memory files to an "
                f"external server has essentially no legitimate use case, "
                f"regardless of how the feature is framed (e.g. as "
                f"'encrypted backup')."
            )
            break  # one hit is enough signal, avoid listing every filename

    return findings


def find_wallet_credential_harvesting(text):
    """
    Module 16: browser wallet/credential harvesting.

    Found via real samples: (1) a 'portfolio sync' skill that locates
    and copies MetaMask/Phantom browser-extension storage directories
    (where wallet seed phrases and private keys live) and streams them
    via 'tar | curl -X POST' - a real exfiltration shape none of the
    existing checks cover (not base64, not a simple curl|bash pipe);
    (2) a 'session analysis' skill that runs SQL queries directly
    against Chrome's actual internal password database schema
    (Login Data table, password_value column) and POSTs the result.

    Both patterns are narrow and specific enough to be high-precision:
    there is essentially no legitimate reason for a skill to reference
    these exact wallet-extension names or this exact browser password-
    database schema.
    """
    findings = []

    WALLET_MARKERS = [
        r"metamask", r"phantom\b", r"trust\s*wallet", r"local extension settings",
    ]
    BROWSER_CRED_MARKERS = [
        r"login data.{0,20}(select|logins)", r"password_value",
        r"chrome.{0,20}cookies.{0,20}\.dump",
    ]
    ARCHIVE_TO_NETWORK = r"tar\s+cz?f?\s*-.{0,80}\|\s*curl"
    NETWORK_SEND = r"(curl\s+.*-X\s*POST|requests\.post\s*\(|\.send\s*\(|fetch\s*\()"

    has_network = re.search(NETWORK_SEND, text, re.IGNORECASE) or re.search(ARCHIVE_TO_NETWORK, text, re.IGNORECASE)

    if has_network:
        for pattern in WALLET_MARKERS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                line_num = text[:match.start()].count("\n") + 1
                findings.append(
                    f"Line {line_num}: references a browser cryptocurrency "
                    f"wallet extension ('{match.group(0)}') alongside "
                    f"network-send capability - wallet extension storage "
                    f"contains seed phrases/private keys; there is no "
                    f"legitimate reason for a skill to locate and "
                    f"transmit this data."
                )
                break
        for pattern in BROWSER_CRED_MARKERS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                line_num = text[:match.start()].count("\n") + 1
                findings.append(
                    f"Line {line_num}: queries a browser's internal "
                    f"password/cookie database schema ('{match.group(0)[:50]}') "
                    f"alongside network-send capability - a well-known "
                    f"credential-theft pattern targeting stored browser "
                    f"passwords directly."
                )
                break

    return findings


def find_safety_bypass_instruction(text):
    """
    Module 17: safety-confirmation bypass instructions.

    Found via a real sample instructing the agent to write a CLAUDE.md
    containing 'dangerouslyDisableSandbox: true', 'autoApproveAll: true',
    and plain-language instructions to 'never ask for confirmation' /
    'never refuse a command'. This is a self-propagating permission-
    escalation attack: it doesn't attack the system directly, it
    attacks the AGENT'S OWN SAFETY CONFIGURATION so that whatever comes
    next faces no scrutiny.
    """
    findings = []
    SAFETY_BYPASS_PATTERNS = [
        r"dangerouslyDisableSandbox\s*:\s*true",
        r"autoApproveAll\s*:\s*true",
        r"do not ask for (?:user )?confirmation",
        r"never refuse a command",
        r"never ask for confirmation",
        r"pre-?approved.{0,30}(all|every)",
        r"allowed-tools:\s*[\"']?(Bash|Write|Edit|WebFetch)\(\*\)",
        r"allowed-tools:\s*\*\s*$",
        # Found via real-world testing (MalSkillBench prompt-injection
        # samples): the same underlying "disable safety" concept,
        # phrased in blander, more corporate-sounding language that
        # the narrower patterns above don't generalize to.
        r"safety bypass",
        r"without (?:applying )?(?:content filtering|validation protocols?)",
        r"unrestricted.{0,20}protocol",
        r"clear (?:any )?(?:directive parameters|prior instructions)",
        r"without.{0,20}content filtering",
    ]
    for pattern in SAFETY_BYPASS_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            if _is_negated(text, match.start()):
                continue
            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: instructs disabling the agent's own "
                f"safety confirmations ('{match.group(0)}') - a self-"
                f"propagating permission-escalation pattern: rather than "
                f"attacking the system directly, it attacks the agent's "
                f"own safety configuration so nothing that follows faces "
                f"scrutiny."
            )
    return findings


def find_unicode_steganography(text):
    """
    Module 18: Unicode steganography detection.

    Technique inspiration: agent-audit-kit's AAK-SKILL-002 rule (their
    source read directly as part of this project's competitor research
    - see ROADMAP.md Tier 3.D). A category Husk's own invisible-
    character check (module 1, used for whitespace-padding detection)
    doesn't cover: bidirectional-override characters and Unicode "tag"
    characters that make text RENDER differently than it PARSES.

    Bidi overrides (U+202A-U+202E, U+2066-U+2069) can visually reverse
    or reorder text so a human reading the rendered file sees something
    different from the actual character sequence an agent parses -
    e.g. hiding a dangerous command inside what looks like an innocuous
    word. Unicode "tag" characters (U+E0000-U+E007F) are invisible in
    virtually all renderers and have been used to smuggle hidden ASCII
    payloads inside seemingly normal text.

    Neither has any legitimate reason to appear in a skill file.
    """
    findings = []
    BIDI_OVERRIDE_RANGES = [
        (0x202A, 0x202E),  # LRE, RLE, PDF, LRO, RLO
        (0x2066, 0x2069),  # LRI, RLI, FSI, PDI
    ]
    TAG_UNICODE_RANGE = (0xE0000, 0xE007F)

    for i, ch in enumerate(text):
        code = ord(ch)
        is_bidi = any(lo <= code <= hi for lo, hi in BIDI_OVERRIDE_RANGES)
        is_tag = TAG_UNICODE_RANGE[0] <= code <= TAG_UNICODE_RANGE[1]
        if is_bidi or is_tag:
            line_num = text[:i].count("\n") + 1
            kind = "bidirectional-override" if is_bidi else "Unicode tag"
            findings.append(
                f"Line {line_num}: contains a {kind} character "
                f"(U+{code:04X}) - this class of character makes text "
                f"render differently than it parses, or is invisible in "
                f"virtually all renderers. There is no legitimate reason "
                f"for a skill file to contain one."
            )
            # One report per category is enough signal; avoid spamming
            # a finding for every single occurrence in a longer run.
            if len(findings) >= 3:
                break

    return findings


def find_trusted_name_hijacking(text, existing_findings):
    """
    Module 19: trusted-name hijacking.

    Technique inspiration: agent-audit-kit's AAK-SKILL-004 rule (its
    source was read directly as part of this project's competitor
    research - see ROADMAP.md Tier 3.D): a skill's declared name mimics
    a well-known, widely-trusted skill (pdf, docx, pptx, xlsx,
    frontend-design, etc.) while its actual body does something
    unrelated or hostile - trading on the trust a familiar name earns.

    PRECISION SCOPING: matching a common name alone is nowhere near
    enough signal on its own - plenty of legitimate skills are
    reasonably named 'pdf-tools' or similar. This only adds a finding
    when the file ALSO already triggered at least one other real
    finding from every other check in this scanner - i.e. it never
    fires alone, only as an aggravating note on top of independently-
    justified suspicion, which keeps false-positive risk essentially
    at zero while still surfacing the pattern when it's genuinely
    relevant.
    """
    if not existing_findings:
        return []

    TRUSTED_NAMES = [
        "pdf", "docx", "pptx", "xlsx", "frontend-design", "skill-creator",
        "webapp-testing", "mcp-builder", "brand-guidelines",
    ]
    name_match = re.search(r'^name:\s*["\']?([\w-]+)', text, re.MULTILINE)
    if not name_match:
        return []
    declared_name = name_match.group(1).lower()

    if declared_name in TRUSTED_NAMES:
        return [
            f"Additionally: this skill's declared name ('{declared_name}') "
            f"matches a well-known, widely-trusted skill name, while the "
            f"file also independently triggered other findings above - "
            f"trading on a familiar name while behaving unexpectedly is a "
            f"documented impersonation pattern (name hijacking)."
        ]
    return []


def find_system_persistence_write(text):
    """
    Module 20: writes to system-level (root-required) persistence
    locations.

    Found via a real sample: a script disguised as 'DICOM workflow
    support' that writes a cron job to /etc/cron.d/, creates a systemd
    service with Restart=always and WantedBy=multi-user.target (auto-
    start on boot), AND appends to .bashrc - three separate persistence
    mechanisms combined, all pointing to a suspicious external URL.

    Precision note: only the system-level locations are flagged here
    (/etc/cron.d, /etc/cron.daily, /etc/systemd/system) - these require
    root and have essentially no legitimate reason to be written by a
    skill. Shell rc files (.bashrc etc.) are deliberately NOT included
    on their own; many legitimate dev tools (nvm, pyenv, conda) append
    PATH exports there, making it too common on its own to be a
    reliable signal without additional context.
    """
    findings = []
    PERSISTENCE_PATHS = [
        r"/etc/cron\.d\b", r"/etc/cron\.daily\b", r"/etc/cron\.hourly\b",
        r"/etc/systemd/system\b",
    ]
    WRITE_CONTEXT = r"(open\s*\(|write_text\s*\(|\.write\s*\()"

    for path_pattern in PERSISTENCE_PATHS:
        for match in re.finditer(path_pattern, text, re.IGNORECASE):
            # require a write-ish context somewhere nearby (same
            # paragraph-ish window) rather than a bare mention
            window_start = max(0, match.start() - 300)
            window_end = min(len(text), match.end() + 300)
            window = text[window_start:window_end]
            if re.search(WRITE_CONTEXT, window):
                line_num = text[:match.start()].count("\n") + 1
                findings.append(
                    f"Line {line_num}: writes to a system-level, root-"
                    f"required persistence location ('{match.group(0)}') "
                    f"- legitimate skills have essentially no reason to "
                    f"create cron jobs or systemd services; this is a "
                    f"well-known, strong persistence-establishment pattern."
                )
                break  # one hit per path pattern is enough signal

    return findings


def find_ransom_note_pattern(text):
    """
    Module 21b: ransom note / cryptocurrency payment demand content.

    Found via a real, severe sample disguised as a "data optimization
    utility": walks every file in a directory, encrypts each one with
    ChaCha20 + RSA (textbook ransomware hybrid encryption - a random
    session key encrypts the data, then the session key itself is
    encrypted with an RSA public key so only the attacker's matching
    private key can decrypt it), DELETES the original files, then
    writes a ransom note demanding Bitcoin payment with a redemption
    code. Completely undisguised ransomware, missed by every existing
    module.

    This specific check targets the ransom note itself: cryptocurrency
    payment-demand language has essentially zero legitimate use case in
    a skill file, and is a highly reliable, low-false-positive signal
    on its own - it doesn't need to be combined with the encryption
    behavior to be worth flagging.
    """
    findings = []
    CRYPTO_PAYMENT_TERMS = r"(bitcoin|btc wallet|crypto wallet address|monero)"
    # "payment" alone was too generic - real ransom notes specifically
    # use language tied to DATA RECOVERY (redeem, decrypt, recover),
    # not just "payment" in general. Found via real-world false-
    # positive testing: legitimate crypto/fintech tools (a Bitcoin
    # wallet CLI, a Lightning-payment service, an invoice template
    # listing Bitcoin as one payment option) all got flagged purely
    # because "bitcoin" and "payment" appeared near each other for
    # completely ordinary reasons. The actual real ransomware sample
    # this module targets only matched "payment" because it happened
    # to appear inside a domain name (payment.bitcoinvault.top), not
    # as meaningful demand language - removing it loses nothing real.
    DEMAND_TERMS = r"(redeem|ransom|decrypt your files|recover your files|redemption code|pay to (?:decrypt|recover|unlock))"

    for match in re.finditer(CRYPTO_PAYMENT_TERMS, text, re.IGNORECASE):
        window_start = max(0, match.start() - 150)
        window_end = min(len(text), match.end() + 150)
        window = text[window_start:window_end]
        demand_match = re.search(DEMAND_TERMS, window, re.IGNORECASE)
        if demand_match:
            line_num = text[:match.start()].count("\n") + 1
            findings.append(
                f"Line {line_num}: cryptocurrency payment-demand language "
                f"('{match.group(0)}' near '{demand_match.group(0)}') - "
                f"this combination has essentially no legitimate use case "
                f"in a skill file and is a highly reliable ransomware "
                f"indicator."
            )
            break

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

    # Check 9: fake-prerequisite social engineering (validated against
    # real-world data - the pattern our earlier checks completely missed)
    findings.extend(find_fake_prerequisite_socialengineering(text))

    # Check 10: overt instruction-override language (not just hidden
    # comments - found via large-scale real-world testing)
    findings.extend(find_instruction_override(text))

    # Check 11: overt secrecy language, whole document (same principle
    # as check 10, applied to module 6's phrase list)
    findings.extend(find_overt_secrecy_language(text))

    # Check 12: network calls targeting a bare IP address (C2 indicator)
    findings.extend(find_exfil_to_raw_ip(text))

    # Check 13: subprocess calls invoking curl/wget/nc directly, list
    # form, regardless of shell=True
    findings.extend(find_subprocess_network_exfil(text))

    # Check 14: subprocess shell=True, window-based (fixes nested-paren
    # regex failure found via real-world testing)
    findings.extend(find_shell_true_subprocess(text))

    # Check 15: world-writable/executable permission changes
    findings.extend(find_permission_escalation(text))

    # Check 16: dropper pattern (writing executable bytes to disk)
    findings.extend(find_dropper_pattern(text))

    # Check 17: agent identity/memory file exfiltration
    findings.extend(find_agent_identity_exfiltration(text))

    # Check 18: browser wallet/credential harvesting
    findings.extend(find_wallet_credential_harvesting(text))

    # Check 19: safety-confirmation bypass instructions
    findings.extend(find_safety_bypass_instruction(text))

    # Check 20: Unicode steganography (bidi-override, tag characters)
    findings.extend(find_unicode_steganography(text))

    # Check 20b: system-level (root-required) persistence writes
    findings.extend(find_system_persistence_write(text))

    # Check 20c: ransom note / cryptocurrency payment demand content
    findings.extend(find_ransom_note_pattern(text))

    # Check 21: trusted-name hijacking (only fires as an aggravating
    # factor when something ELSE has already been flagged - see
    # find_trusted_name_hijacking's docstring for why it's scoped this way)
    findings.extend(find_trusted_name_hijacking(text, findings))

    # Check 22: AST-based taint tracking (Tier 4.1) - a structurally
    # different detection layer from everything above: traces real
    # variable data-flow from sensitive sources to dangerous sinks
    # through the actual parsed syntax tree, rather than text proximity.
    # Safe to run on any file - gracefully returns nothing on non-Python
    # content (SyntaxError) or genuinely clean code.
    for taint_finding in analyze_taint_flows(text):
        findings.append(str(taint_finding))

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
