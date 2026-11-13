"""Exercise the Windows AppContainer boundary using a fixed native fixture."""

import os
import re
import select
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from uuid import uuid4

import pytest

from ai_threat_lab.agent_fs import pinned_read_scope
from ai_threat_lab.models import ValidationError

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows AppContainer")


@pytest.fixture(scope="module")
def appcontainer_executable(tmp_path_factory):
    tools_root = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio" / "Installer"
    vswhere = tools_root / "vswhere.exe"
    installation = ""
    if vswhere.is_file():
        installation = subprocess.check_output([
            vswhere, "-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath",
        ], text=True, timeout=15).strip()
    vcvars = Path(installation) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    if not installation or not vcvars.is_file():
        if os.environ.get("THREAT_LAB_REQUIRE_APPCONTAINER_PROBE") == "1":
            pytest.fail("MSVC x64 tools required for AppContainer acceptance")
        pytest.skip("MSVC x64 tools unavailable")
    root = tmp_path_factory.mktemp("appcontainer-build")
    source = Path(__file__).with_name("fixtures") / "appcontainer_probe.c"
    (root / source.name).write_bytes(source.read_bytes())
    build = root / "build.cmd"
    build.write_text(
        '@echo off\ncall "%ATL_TEST_VCVARS%" >nul\nif errorlevel 1 exit /b 1\n'
        'cl /nologo /W4 /WX /MT /Fe:probe.exe appcontainer_probe.c '
        'userenv.lib advapi32.lib ws2_32.lib\n',
        encoding="ascii",
    )
    result = subprocess.run(
        [os.environ["COMSPEC"], "/d", "/c", build.name], cwd=root,
        env={**os.environ, "ATL_TEST_VCVARS": str(vcvars)},
        capture_output=True, text=True, timeout=90,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return root / "probe.exe"


@pytest.fixture
def appcontainer(appcontainer_executable, tmp_path):
    from _winapi import CreateJunction

    root = tmp_path / "AppContainer fixture żółć"
    root.mkdir()
    probe = root / "probe.exe"
    probe.write_bytes(appcontainer_executable.read_bytes())
    for name in ("input", "private", "scratch"):
        (root / name).mkdir()
    (root / "input" / "approved.txt").write_bytes(b"x")
    (root / "private" / "canary.txt").write_bytes(b"private synthetic fixture")
    CreateJunction(str(root / "private"), str(root / "input" / "junction"))
    try:
        (root / "input" / "symlink").symlink_to(root / "private" / "canary.txt")
    except OSError as error:
        if error.winerror != 1314:
            raise
    profile = "ThreatLab.M4." + uuid4().hex

    def invoke(*args):
        return subprocess.run([probe, *args], cwd=root, capture_output=True, text=True, timeout=20)

    created = invoke("create", profile)
    assert created.returncode == 0, created.stderr
    try:
        sid = created.stdout.strip()
        assert re.fullmatch(r"S-1-15-2(?:-\d+){7}", sid), sid
        acl = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
        for path, rights in (
            (root, "(RX)"), (probe, "(RX)"), (root / "input", "(OI)(CI)(RX)"),
            (root / "input" / "approved.txt", "(R)"),
            (root / "scratch", "(OI)(CI)(M)"),
        ):
            result = subprocess.run(
                [acl, path, "/grant", f"*{sid}:{rights}"],
                capture_output=True, text=True, errors="replace", timeout=15,
            )
            assert result.returncode == 0, result.stdout + result.stderr
        result = subprocess.run(
            [acl, root / "scratch", "/setintegritylevel", "(OI)(CI)L"],
            capture_output=True, text=True, errors="replace", timeout=15,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        yield root, probe, profile
    finally:
        deleted = invoke("delete", profile)
        assert deleted.returncode == 0, deleted.stderr


@pytest.fixture
def loopback_servers():
    with ExitStack() as stack:
        endpoints = []
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                server = stack.enter_context(socket.socket(family, kind))
                server.bind((host, 0))
                server.settimeout(3)
                endpoints.append(server)
                with socket.socket(family, kind) as client:
                    client.settimeout(3)
                    if kind == socket.SOCK_STREAM:
                        server.listen()
                        client.connect(server.getsockname())
                        connection, _ = server.accept()
                        connection.close()
                    else:
                        client.sendto(b"host control", server.getsockname())
                        assert server.recv(32) == b"host control"
        yield endpoints
        assert not select.select(endpoints, [], [], 0.2)[0], "Loopback received sandbox traffic"


def probe_command(appcontainer, loopback_servers, mode):
    root, probe, profile = appcontainer
    ports = [str(server.getsockname()[1]) for server in loopback_servers]
    symlink = "symlink" if (root / "input" / "symlink").is_symlink() else "unavailable"
    return [probe, "launch", profile, *ports, mode, symlink], {
        "cwd": root,
        "env": {key: os.environ[key] for key in (
            "SystemRoot", "SystemDrive", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
        )},
    }


@pytest.mark.parametrize("mode,expected", [("normal", 0), ("wait", 124)])
def test_appcontainer_files_network_and_timeout(appcontainer, loopback_servers, mode, expected):
    root, _, _ = appcontainer
    command, options = probe_command(appcontainer, loopback_servers, mode)
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=20, **options,
    )
    assert result.returncode == expected, (result.returncode, result.stderr)
    assert (root / "scratch" / "ready").is_file()
    assert (root / "scratch" / "result").read_bytes() == b"x"
    assert (root / "input" / "approved.txt").read_bytes() == b"x"
    assert (root / "private" / "canary.txt").read_bytes() == b"private synthetic fixture"
    assert not (root / "outside.txt").exists()


def test_appcontainer_job_ends_worker_when_launcher_dies(appcontainer, loopback_servers):
    import _winapi

    root, _, _ = appcontainer
    command, options = probe_command(appcontainer, loopback_servers, "wait")
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **options,
    ) as launcher:
        try:
            deadline = time.monotonic() + 8
            while not (root / "scratch" / "ready").exists() and launcher.poll() is None:
                assert time.monotonic() < deadline, "AppContainer payload did not reach readiness"
                time.sleep(0.05)
            if launcher.poll() is not None:
                pytest.fail(
                    f"Launcher exited early: {launcher.returncode}, {launcher.stderr.read()}"
                )
            pid = int(launcher.stdout.readline())
            handle = _winapi.OpenProcess(0x00100000, False, pid)
            try:
                assert _winapi.WaitForSingleObject(handle, 0) == 258
                launcher.kill()
                launcher.wait(timeout=5)
                assert _winapi.WaitForSingleObject(handle, 5000) == 0
            finally:
                _winapi.CloseHandle(handle)
        finally:
            if launcher.poll() is None:
                launcher.kill()


def test_pinned_windows_input_rejects_directory_substitution(appcontainer):
    root, _, _ = appcontainer
    approved = root / "input"
    identity = approved.stat()
    displaced = root / "displaced"
    with pinned_read_scope(approved, expected=identity):
        with pytest.raises(PermissionError):
            approved.rename(displaced)
    approved.rename(displaced)
    approved.mkdir()
    with pytest.raises(ValidationError, match="changed since selection"):
        with pinned_read_scope(approved, expected=identity):
            pytest.fail("replacement entered approved scope")
