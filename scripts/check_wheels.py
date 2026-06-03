"""Verify wheels in radkit-wheels/ match the running interpreter.

Exits with a non-zero status and a friendly, specific message if the
wheels the engineer dropped don't match this Python + OS + arch combo.

Used by run.sh, SDA-Pathfinder.command, and scripts/launcher.ps1
before they hand the folder to pip — so engineers get "delete those
and re-download these" instead of pip's cryptic
"is not a supported wheel on this platform".
"""

import glob
import os
import platform
import re
import sys

WHEEL_DIR = "radkit-wheels"
PACKAGES = ("cisco_radkit_client", "cisco_radkit_common",
            "cisco_radkit_genie", "cisco_radkit_service")


def expected_tags() -> tuple[str, str, str]:
    py_tag = f"cp{sys.version_info.major}{sys.version_info.minor}"
    arch = platform.machine().lower()
    sysname = platform.system().lower()
    if sysname == "darwin":
        platform_re = (rf"macosx_[0-9_]+_arm64"
                       if arch in ("arm64", "aarch64")
                       else rf"macosx_[0-9_]+_x86_64")
        os_label = f"macOS ({arch})"
    elif sysname == "linux":
        platform_re = rf"manylinux[^.]*_x86_64"
        os_label = "Linux x86_64"
    elif sysname == "windows":
        platform_re = r"win_amd64"
        os_label = "Windows x64"
    else:
        platform_re = r".*"
        os_label = sysname
    return py_tag, platform_re, os_label


def main() -> int:
    py_tag, platform_re, os_label = expected_tags()
    wheel_re = re.compile(rf".*-{py_tag}-[^-]+-{platform_re}\.whl$")

    files = sorted(
        os.path.basename(f)
        for f in glob.glob(os.path.join(WHEEL_DIR, "cisco_radkit_*.whl"))
    )

    matched_pkgs: set[str] = set()
    for f in files:
        if not wheel_re.match(f):
            continue
        for pkg in PACKAGES:
            if f.startswith(pkg + "-"):
                matched_pkgs.add(pkg)

    missing = [p for p in PACKAGES if p not in matched_pkgs]
    if not missing:
        return 0

    sys.stderr.write(
        "\n"
        "================================================================\n"
        f"  Wheels in ./{WHEEL_DIR}/ don't match this system\n"
        "================================================================\n"
        "\n"
        f"  This machine:\n"
        f"    Python:   {sys.version_info.major}.{sys.version_info.minor} "
        f"(tag: {py_tag})\n"
        f"    OS/arch:  {os_label}\n"
        "\n"
        f"  You need wheels whose filenames end in:\n"
        f"    {py_tag}-none-<{platform_re}>.whl\n"
        "\n"
    )
    if files:
        sys.stderr.write("  Wheels currently in the folder:\n")
        for f in files:
            sys.stderr.write(f"    - {f}\n")
        sys.stderr.write("\n")
    sys.stderr.write(
        f"  Missing matching wheel for: {', '.join(missing)}\n"
        "\n"
        "  Fix:\n"
        f"    1. Delete every file in ./{WHEEL_DIR}/.\n"
        "    2. Go to https://radkit.cisco.com/downloads/release/\n"
        "    3. Pick RADKit 1.9.9 and download the four wheels matching\n"
        f"       this machine ({py_tag} + {os_label}).\n"
        f"    4. Drop the four .whl files into ./{WHEEL_DIR}/.\n"
        "    5. Run the launcher again.\n"
        "\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
