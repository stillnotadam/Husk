"""
Husk - the aggregator: combines Husk's own verdict on an already-
published skill with whatever other independent auditors have already
said about the exact same skill, into one summarized answer. Works
across any registered skill marketplace, not just one.

WHY THIS EXISTS
----------------
Husk's core scanner answers "is this skill safe" for content that may
never have been looked at by anyone else - the case that matters most
before something is published. This module answers a different,
narrower question: for a skill that's ALREADY live on a real
marketplace, several independent tools may already have an opinion
(a marketplace's own built-in audit, Socket, and others), and those
opinions don't always agree - confirmed directly, not assumed: the
exact same skill rated "Warn" by one auditor and "Fail"/HIGH risk by
another. That disagreement is itself the real, useful signal - Husk's
job here is to collect it and add its own verdict, not to declare
itself the one true answer, and never to imply endorsement by, or
dependency on, any one marketplace.

REAL, STATED ARCHITECTURE CHOICE
----------------------------------
Every marketplace's content-resolver and every external opinion
source is its own separate, independently-registered adapter, and a
failure in any one of them (the site changes its layout, goes down,
blocks scraping) degrades ONLY that one piece, never the whole
aggregate - the same graceful-degradation posture as every other
optional layer in this project (LLM review, VirusTotal). ClawHub's
resolver and native-audit adapter are fully real and verified against
their real, documented CLI. Other marketplaces are registered with a
clear, honest TODO rather than a fragile scraper built against a page
structure that was only ever manually inspected a few times and never
verified stable or within that site's own terms of use - that
verification is real, separate work per marketplace, not glossed over
here.
"""

import io
import json
import os
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Callable, Optional

from .package_scanner import scan_package
from .skill_scanner import scan_skill_file

# marketplace name -> resolver function (skill_ref -> local content path
# or None). Each marketplace registers its own way of turning a skill
# reference into real, local content Husk can actually scan.
MARKETPLACE_RESOLVERS: dict[str, Callable[[str], Optional[str]]] = {}


def register_marketplace(name):
    """Decorator: adds a content-resolver function to
    MARKETPLACE_RESOLVERS under `name`, so aggregate_skill_opinions can
    dispatch to the right marketplace without hardcoding the list."""
    def _decorator(fn):
        MARKETPLACE_RESOLVERS[name] = fn
        return fn
    return _decorator


# One entry per known external opinion source (a marketplace's own
# built-in audit, a third-party auditor like Socket, etc). Each
# adapter takes a skill reference and returns either a real result or
# None if unavailable - never raises, matching every other optional
# layer in this project. Kept as one flat registry rather than scoped
# per-marketplace, since a real auditor (Socket, confirmed via this
# project's own research) can independently audit skills that surface
# through more than one marketplace at once.
EXTERNAL_SOURCES: dict[str, Callable[[str], Optional[dict]]] = {}


# Which marketplaces each external source applies to (None = all). A
# marketplace's own audit (e.g. ClawHub's) must only be consulted for
# skills that actually came from that marketplace.
_SOURCE_SCOPE: dict[str, Optional[set]] = {}


def register_external_source(name, marketplaces=None):
    """Decorator: adds a fetch function to EXTERNAL_SOURCES under
    `name`, so aggregate_skill_opinions can call every registered
    source uniformly without hardcoding the list in two places.
    `marketplaces` optionally restricts the source to those marketplaces."""
    def _decorator(fn):
        EXTERNAL_SOURCES[name] = fn
        _SOURCE_SCOPE[name] = set(marketplaces) if marketplaces else None
        return fn
    return _decorator


# ---------------------------------------------------------------------
# ClawHub - built on ClawHub's documented public REST API
# (docs.openclaw.ai/clawhub/http-api). Public read endpoints need no
# token and are explicitly allowed for third-party tools, provided
# results are cached/rate-limit-aware and link back to the canonical
# ClawHub page. The previous version shelled out to `npx clawhub`,
# which (a) called a CLI command that does not return stored verdicts
# and (b) depended on Node.js being present on the server - it failed
# in production. Plain HTTPS has neither problem.
# ---------------------------------------------------------------------

CLAWHUB_API = "https://clawhub.ai"
_HTTP_TIMEOUT_SECONDS = 20
_USER_AGENT = "husk-scanner (+https://github.com/ctrl-adam/Husk)"
_MAX_ARCHIVE_BYTES = 10 * 1024 * 1024     # ClawHub's own raw download cap
_MAX_EXTRACTED_BYTES = 50 * 1024 * 1024   # zip-bomb guard


def parse_clawhub_ref(skill_ref):
    """Accepts 'slug', 'owner/slug', '@owner/slug', 'owner/skills/slug'
    or a clawhub.ai URL. Returns (owner_or_None, slug)."""
    ref = (skill_ref or "").strip()
    if ref.startswith(("http://", "https://")):
        ref = urllib.parse.urlparse(ref).path
    parts = [x for x in ref.strip("/").split("/") if x]
    if not parts:
        return None, ""
    if len(parts) == 1:
        return None, parts[0].lstrip("@")
    owner = parts[0].lstrip("@").lower() or None
    return owner, parts[-1]


def clawhub_skill_url(owner, slug):
    """Canonical ClawHub page (their terms ask third parties to link back)."""
    if owner:
        return f"{CLAWHUB_API}/{owner}/skills/{slug}"
    return f"{CLAWHUB_API}/search?q={urllib.parse.quote(slug)}"


def _http(method, url, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json, */*"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)  # noqa: S310 - fixed https base URL
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SECONDS) as resp:  # noqa: S310
        payload = resp.read(_MAX_ARCHIVE_BYTES + 1)
        if len(payload) > _MAX_ARCHIVE_BYTES:
            raise ValueError("response larger than the 10MB limit")
        return resp.headers.get("Content-Type", ""), payload


def _describe_error(exc, slug):
    """Turn a failure into a message a user can act on."""
    if isinstance(exc, urllib.error.HTTPError):
        try:
            detail = exc.read().decode("utf-8", "replace").strip()[:200]
        except Exception:
            detail = ""
        if exc.code == 404:
            return f"ClawHub has no public skill '{slug}' (404). Check the name - try 'owner/skill-name' as shown on clawhub.ai."
        if exc.code == 429:
            return "ClawHub rate limit reached - try again in a minute."
        if exc.code in (403, 410):
            return f"ClawHub refused the download ({exc.code}): {detail or 'blocked or removed version'}."
        return f"ClawHub returned HTTP {exc.code}: {detail}"
    if isinstance(exc, urllib.error.URLError):
        return f"Could not reach ClawHub ({exc.reason})."
    return f"{type(exc).__name__}: {exc}"


def _inside(base, target):
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return os.path.commonpath([base, target]) == base


def _safe_extract(archive_bytes, dest):
    """Extract a zip or tar archive into dest, refusing path traversal,
    links and oversized content. Archive contents are untrusted input."""
    total = 0
    if archive_bytes[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                target = os.path.join(dest, info.filename)
                if not _inside(dest, target):
                    continue
                total += info.file_size
                if total > _MAX_EXTRACTED_BYTES:
                    raise ValueError("archive expands beyond the 50MB safety limit")
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        return
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue  # skips dirs, symlinks, hardlinks, devices
            target = os.path.join(dest, member.name)
            if not _inside(dest, target):
                continue
            total += member.size
            if total > _MAX_EXTRACTED_BYTES:
                raise ValueError("archive expands beyond the 50MB safety limit")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def _find_skill_root(extracted, hint_path=""):
    """Locate the directory holding the skill inside an extracted archive."""
    hint = hint_path.strip("/")
    for root, _dirs, files in os.walk(extracted):
        rel = os.path.relpath(root, extracted).replace(os.sep, "/")
        if hint and not (rel == hint or rel.endswith("/" + hint)):
            continue
        if "SKILL.md" in files or hint:
            return root
    for root, _dirs, files in os.walk(extracted):
        if "SKILL.md" in files:
            return root
    return extracted if os.listdir(extracted) else None


def fetch_clawhub_skill(skill_ref, workdir=None):
    """Download a public ClawHub skill's real files. Returns
    (directory_or_None, error_message_or_None). Never raises.

    Uses GET /api/v1/download?slug=..., which returns the hosted skill
    as a ZIP, or - for GitHub-backed skills - a JSON handoff pointing at
    the public GitHub archive, which is then fetched instead.
    """
    _owner, slug = parse_clawhub_ref(skill_ref)
    if not slug:
        return None, "Enter a ClawHub skill name, e.g. 'owner/skill-name'."
    workdir = workdir or tempfile.mkdtemp(prefix="husk_clawhub_")
    try:
        url = f"{CLAWHUB_API}/api/v1/download?slug={urllib.parse.quote(slug)}"
        ctype, payload = _http("GET", url)
        hint = ""
        if "json" in ctype or payload[:1] == b"{":
            handoff = json.loads(payload.decode("utf-8"))
            archive_url = handoff.get("archiveUrl")
            if not archive_url or not archive_url.startswith("https://"):
                return None, "ClawHub returned a GitHub handoff without a usable archive URL."
            hint = handoff.get("path") or ""
            _ctype, payload = _http("GET", archive_url)
        _safe_extract(payload, workdir)
        root = _find_skill_root(workdir, hint)
        if not root:
            return None, "The downloaded archive was empty."
        return root, None
    except Exception as exc:  # network, HTTP, archive, JSON - all reported, never raised
        return None, _describe_error(exc, slug)


def resolve_clawhub_skill(skill_ref, workdir=None):
    """Path-only convenience wrapper around fetch_clawhub_skill."""
    path, _error = fetch_clawhub_skill(skill_ref, workdir)
    return path


@register_marketplace("clawhub")
def _resolve_clawhub_for_aggregate(skill_ref, workdir=None):
    return fetch_clawhub_skill(skill_ref, workdir)


@register_external_source("clawhub_native", marketplaces=["clawhub"])
def _fetch_clawhub_native_audit(skill_ref):
    """ClawHub's own published security verdict for the latest version.

    Primary: POST /api/v1/skills/-/security-verdicts (compact verdicts).
    Fallback: the `moderation.verdict` field of GET /api/v1/skills/{slug},
    whose real shape was confirmed from a live curl output posted in
    openclaw/openclaw issue #92077 (June 2026). The fallback means one
    endpoint changing or failing does not blank out ClawHub's verdict."""
    owner, slug = parse_clawhub_ref(skill_ref)
    if not slug:
        return {"available": False, "error": "no skill name given"}
    try:
        _ct, raw = _http("GET", f"{CLAWHUB_API}/api/v1/skills/{urllib.parse.quote(slug)}")
        detail = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return {"available": False, "error": _describe_error(exc, slug)}

    version = (detail.get("latestVersion") or {}).get("version")
    owner = owner or ((detail.get("owner") or {}).get("handle") or "").lower() or None
    skill_url = clawhub_skill_url(owner, slug)
    moderation_verdict = (detail.get("moderation") or {}).get("verdict")

    def _result(status, source, **extra):
        return {"available": True, "flagged": status in ("suspicious", "malicious"),
                "verdict": status, "version": version, "skill_url": skill_url,
                "verdict_source": source, **extra}

    primary_error = None
    if version:
        try:
            item_req = {"slug": slug, "version": version}
            if owner:
                item_req["ownerHandle"] = owner
            _ct, raw = _http("POST", f"{CLAWHUB_API}/api/v1/skills/-/security-verdicts", {"items": [item_req]})
            items = json.loads(raw.decode("utf-8")).get("items") or []
            item = items[0] if items else {}
            status = (item.get("security") or {}).get("status")
            if status in ("clean", "suspicious", "malicious"):
                return _result(status, "security-verdicts",
                               decision=item.get("decision"),
                               audit_url=item.get("securityAuditUrl"),
                               overview=item.get("overview"),
                               skill_url=item.get("skillUrl") or skill_url)
            primary_error = (item.get("error") or {}).get("message") or f"no definitive verdict (status: {status})"
        except Exception as exc:
            primary_error = _describe_error(exc, slug)
    else:
        primary_error = "skill has no public version on ClawHub"

    if moderation_verdict in ("clean", "suspicious", "malicious"):
        return _result(moderation_verdict, "moderation")
    return {"available": False, "error": primary_error}


@register_marketplace("skillssh")
def resolve_skillssh_skill(skill_ref, workdir=None):
    """
    TODO, real and stated, not hidden: skills.sh (Vercel's skill
    registry, already a named comparison point elsewhere in this
    project - see README.md's own intro line) was confirmed real via
    this project's own research, including that it publishes detailed,
    real, per-skill security audit pages from multiple named third-
    party auditors (Socket, and a separate one referred to in this
    project's research as "Gen Agent Trust Hub"). What hasn't been
    built or verified yet is a real, stable, sanctioned way to fetch a
    given skill's actual content from skills.sh programmatically -
    unlike ClawHub, no official CLI for this was found during that
    research. Returns None (source unavailable) until that's actually
    verified and built, the same honest posture as every other
    unverified adapter in this file.
    """
    return None


@register_marketplace("agentskillsh")
def resolve_agentskillsh_skill(skill_ref, workdir=None):
    """
    Downloads a skill's real content from agentskill.sh, using their
    own documented, machine-readable API built specifically for this -
    confirmed directly by fetching a real skill's page and reading
    their own "How to install this skill programmatically (for AI
    agents)" section, not guessed at: GET /api/agent/skills/<owner
    URL-encoded '/' skill>/install, returning JSON with a "skillMd"
    field (the real SKILL.md content) and a "skillFiles" array (any
    additional files). This is their own sanctioned mechanism, not a
    scraper built against page structure that was only manually
    inspected a few times.

    Honest, stated limitation, the same posture as resolve_clawhub_skill
    above: the real network call to agentskill.sh could not be
    completed FROM THIS DEVELOPMENT SANDBOX specifically - confirmed
    directly (a real "host not in allowlist" response, not assumed) -
    its network policy allows the research tools used to find and
    confirm this real API in the first place, but not a live call from
    this module's own code. That is a constraint of this one
    environment, not of the mechanism itself or of a real deployment.
    Returns the local directory the skill's content was written into,
    or None if the request fails for any reason - never raises.
    """
    skill_slug = skill_ref.lstrip("@")
    encoded_slug = urllib.parse.quote(skill_slug, safe="")
    api_url = f"https://agentskill.sh/api/agent/skills/{encoded_slug}/install"

    try:
        req = urllib.request.Request(  # noqa: S310 - fixed https:// URL to agentskill.sh's own documented API, not user-controlled
            api_url, headers={"User-Agent": "husk-scanner (github.com/ctrl-adam/Husk)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed URL, not user input
            data = json.loads(resp.read().decode("utf-8"))

        skill_md = data.get("skillMd")
        if not skill_md:
            return None

        workdir = workdir or tempfile.mkdtemp(prefix="husk_agentskillsh_")
        with open(os.path.join(workdir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(skill_md)

        for extra_file in data.get("skillFiles", []):
            rel_path = extra_file.get("path")
            content = extra_file.get("content")
            if not rel_path or content is None:
                continue
            full_path = os.path.join(workdir, rel_path)
            # Real defensive check: a malicious or malformed API response
            # could supply a path designed to escape workdir (e.g.
            # "../../etc/something") - refuse anything that resolves
            # outside the intended directory rather than trust it blindly.
            if os.path.commonpath([os.path.abspath(full_path), os.path.abspath(workdir)]) != os.path.abspath(workdir):
                continue
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)

        return workdir
    except (urllib.error.URLError, json.JSONDecodeError, OSError, ValueError):
        return None


def aggregate_skill_opinions(skill_ref, marketplace="clawhub", local_path=None,
                              external_results=None, auto_fetch=True):
    """
    Combines Husk's own verdict with whatever external sources are
    actually available right now. Deliberately takes external_results
    as an optional, directly-injectable argument (not just internal
    fetching) - the same design already proven useful elsewhere in
    this project (review_with_consensus takes an explicit provider
    list rather than always auto-discovering) - so this can be tested,
    and used, with real data pulled by hand or by a future adapter,
    without waiting on every scraper to exist first.

    marketplace: which registered marketplace to resolve skill_ref
    against (default "clawhub", the only one with a fully real,
    verified resolver right now - see MARKETPLACE_RESOLVERS and each
    marketplace's own docstring for what's real vs. still a stated
    TODO). Unknown marketplace names are treated the same as a failed
    resolution - reported honestly, never raise.

    local_path: if the skill's own content is already available
    locally (downloaded, checked out), Husk's own scan runs against
    it directly, and marketplace/auto_fetch are skipped for content
    resolution entirely (local_path always wins when given). Without
    it, and with auto_fetch=True (the default), this dispatches to
    the chosen marketplace's own registered resolver to download the
    skill's real content first. If neither a local path nor a
    successful auto-fetch is available, Husk's own opinion is reported
    as unavailable rather than skipped silently - the aggregate should
    never look complete when a piece of it didn't actually run.

    auto_fetch also gates every registered external-source adapter,
    not just marketplace content resolution - with it False, nothing
    in this call reaches out to a live system at all, every source is
    reported unavailable unless supplied directly via external_results.
    A real bug found and fixed while testing this: auto_fetch=False
    originally only stopped content resolution, while the external
    adapters (which now make their own real subprocess calls) kept
    firing regardless - a test suite that should run in well under a
    second was silently taking 20+ seconds waiting on doomed network
    calls it never meant to make.

    Returns: {"skill": skill_ref, "marketplace": marketplace,
    "opinions": {source_name: result}, "summary": {"total_sources":
    int, "flagged_by": int, "agreement":
    "unanimous"|"majority"|"split"|"single_source"|None}} - "summary"
    describes agreement the same honest way review_with_consensus
    already does elsewhere in this project, not a new, inconsistent
    shape invented just for this.
    """
    opinions = {}
    resolve_error = None
    scan_target = local_path

    if not scan_target and auto_fetch:
        resolver = MARKETPLACE_RESOLVERS.get(marketplace)
        if resolver is None:
            resolve_error = f"Unknown marketplace '{marketplace}'."
        else:
            out = resolver(skill_ref)
            # Resolvers may return a path, or (path, error) to explain failures.
            scan_target, resolve_error = out if isinstance(out, tuple) else (out, None)

    if scan_target and os.path.exists(scan_target):
        try:
            if os.path.isdir(scan_target):
                findings = scan_package(scan_target)
                result = {"verdict": "FLAGGED" if findings else "SAFE", "findings": findings}
            else:
                result = scan_skill_file(scan_target)
            opinions["husk"] = {
                "available": True,
                "flagged": result["verdict"] == "FLAGGED",
                "verdict": result["verdict"],
                "findings": result["findings"],
            }
        except Exception as e:
            opinions["husk"] = {"available": False, "error": str(e)}
    else:
        opinions["husk"] = {
            "available": False,
            "error": resolve_error or (
                f"Could not get this skill's content from '{marketplace}', so Husk's "
                f"own scan did not run. Pass local_path directly if you already have it."
            ),
        }

    for source_name, fetch_fn in EXTERNAL_SOURCES.items():
        scope = _SOURCE_SCOPE.get(source_name)
        if scope is not None and marketplace not in scope:
            continue
        if not auto_fetch:
            opinions[source_name] = {
                "available": False,
                "error": "auto_fetch=False - no live external calls were made.",
            }
            continue
        external = fetch_fn(skill_ref)
        opinions[source_name] = external if external is not None else {
            "available": False,
            "error": f"{source_name} returned no result.",
        }

    if external_results:
        for source_name, result in external_results.items():
            opinions[source_name] = result

    available = {name: r for name, r in opinions.items() if r.get("available")}
    flagged = {name: r for name, r in available.items() if r.get("flagged")}

    total_available = len(available)
    if total_available == 0:
        agreement = None
    elif total_available == 1:
        agreement = "single_source"
    elif len(flagged) == 0 or len(flagged) == total_available:
        agreement = "unanimous"
    elif len(flagged) > total_available - len(flagged):
        agreement = "majority_flagged"
    elif len(flagged) < total_available - len(flagged):
        agreement = "majority_clear"
    else:
        agreement = "split"

    source_url = None
    if marketplace == "clawhub":
        native = opinions.get("clawhub_native") or {}
        owner, slug = parse_clawhub_ref(skill_ref)
        source_url = native.get("skill_url") or (clawhub_skill_url(owner, slug) if slug else None)

    return {
        "skill": skill_ref,
        "marketplace": marketplace,
        "source_url": source_url,
        "opinions": opinions,
        "summary": {
            "total_sources": total_available,
            "flagged_by": len(flagged),
            "agreement": agreement,
        },
    }
