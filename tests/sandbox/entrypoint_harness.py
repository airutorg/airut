# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Harness for running generated container entrypoints on the host."""

import shutil
import struct
import subprocess
from pathlib import Path

from airut.sandbox._entrypoint import (
    AGENT_ENTRYPOINT_SCRIPT,
    ENV_HOOK_PATH,
    PASSTHROUGH_ENTRYPOINT_SCRIPT,
    SYSTEM_CA_BUNDLE,
)
from airut.sandbox._network import CA_CONTAINER_PATH
from airut.sandbox.claude_binary import CLAUDE_BINARY_CONTAINER_PATH


BASH = shutil.which("bash")

# ELF program header type of the interpreter (dynamic loader) path.
_PT_INTERP = 3

# Tools the entrypoint needs from PATH, plus ``cat`` and ``printenv``
# for test commands.  ``update-ca-certificates`` is deliberately absent
# unless a test adds it.
_TOOLS = ("cat", "mkdir", "mv", "printenv", "rm")

SCRIPTS = {
    "agent": AGENT_ENTRYPOINT_SCRIPT,
    "passthrough": PASSTHROUGH_ENTRYPOINT_SCRIPT,
}


class FakeContainer:
    """Fake container root for running an entrypoint on the host.

    Rewrites the container paths in the script to locations under
    *root*.  The agent variant's Claude binary is replaced by a stub
    that runs its arguments, so both variants can run the same test
    command.
    """

    def __init__(self, root: Path) -> None:
        assert BASH is not None, "bash not found on host"
        self.root = root
        self.ca = root / "ca.crt"
        self.bundle = root / "etc" / "ssl" / "certs" / "ca-certificates.crt"
        self.hook = root / "etc" / "airut" / "env.sh"
        self.tmp = root / "tmp"
        self.tmp.mkdir()
        self.workdir = root / "workspace"
        self.workdir.mkdir()
        self.bin = root / "bin"
        self.bin.mkdir()
        # Empty directory for tools only reachable from a hook's PATH.
        self.tools = root / "tools"
        self.tools.mkdir()
        for tool in _TOOLS:
            path = shutil.which(tool)
            assert path is not None, f"{tool} not found on host"
            (self.bin / tool).symlink_to(path)
        claude = root / "claude"
        claude.write_text(f'#!{BASH}\nexec "$@"\n')
        claude.chmod(0o755)
        # ``show VAR...`` prints VAR=value (or VAR=<unset>) per argument.
        self.add_tool(
            "show",
            'for v in "$@"; do printf "%s=%s\\n" "$v" "${!v-<unset>}"; done',
        )

    def add_tool(
        self, name: str, body: str, *, directory: Path | None = None
    ) -> None:
        """Add an executable shell script to the container PATH.

        Args:
            name: Tool name.
            body: Script body (bash).
            directory: Where to put the tool; defaults to the PATH dir.
        """
        tool = (directory or self.bin) / name
        tool.write_text(f"#!{BASH}\n{body}\n")
        tool.chmod(0o755)

    def write_hook(self, body: str) -> None:
        """Install an environment hook with *body* in the image."""
        self.hook.parent.mkdir(parents=True, exist_ok=True)
        self.hook.write_text(body + "\n")

    def run(
        self,
        variant: str,
        *command: str,
        env: dict[str, str] | None = None,
        stdin: str = "",
    ) -> subprocess.CompletedProcess[str]:
        """Run the entrypoint *variant* with *command* as arguments."""
        assert BASH is not None
        script = (
            SCRIPTS[variant]
            .replace(CA_CONTAINER_PATH, str(self.ca))
            .replace(SYSTEM_CA_BUNDLE, str(self.bundle))
            .replace(CLAUDE_BINARY_CONTAINER_PATH, str(self.root / "claude"))
            .replace(ENV_HOOK_PATH, str(self.hook))
        )
        script_path = self.root / "entrypoint.sh"
        script_path.write_text(script)
        return subprocess.run(
            [BASH, str(script_path), *command],
            env={"PATH": str(self.bin), "TMPDIR": str(self.tmp), **(env or {})},
            cwd=self.workdir,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=30,
        )


def write_binary_without_loader(dest: Path) -> None:
    """Write a dynamically linked executable whose loader is missing.

    Copies the host's bash (dynamically linked on every mainstream
    distribution) and points its ELF interpreter (PT_INTERP) at a path
    that does not exist -- what the Claude binary looks like in an image
    without the glibc loader.  Executing it fails with ENOENT although
    the file exists, on every bash version.
    """
    assert BASH is not None
    data = bytearray(Path(BASH).resolve().read_bytes())
    assert data[:4] == b"\x7fELF", "host bash is not an ELF binary"
    is_64 = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    if is_64:
        phoff = struct.unpack_from(f"{order}Q", data, 0x20)[0]
        phentsize, phnum = struct.unpack_from(f"{order}HH", data, 0x36)
        field_fmt, offset_field, size_field = f"{order}Q", 8, 32
    else:
        phoff = struct.unpack_from(f"{order}I", data, 0x1C)[0]
        phentsize, phnum = struct.unpack_from(f"{order}HH", data, 0x2A)
        field_fmt, offset_field, size_field = f"{order}I", 4, 16
    for i in range(phnum):
        header = phoff + i * phentsize
        if struct.unpack_from(f"{order}I", data, header)[0] != _PT_INTERP:
            continue
        offset = struct.unpack_from(field_fmt, data, header + offset_field)[0]
        size = struct.unpack_from(field_fmt, data, header + size_field)[0]
        interp = b"/nonexistent/ld.so"
        assert len(interp) < size, "interpreter path too short to patch"
        data[offset : offset + size] = interp.ljust(size, b"\0")
        dest.write_bytes(bytes(data))
        dest.chmod(0o755)
        return
    raise AssertionError("host bash is statically linked (no PT_INTERP)")
