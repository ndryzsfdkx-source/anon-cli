#!/usr/bin/env python3

"""Helper entrypoint for composite action to invoke intellisa scan."""
import os
import shlex
import subprocess
import sys


def _get_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise KeyError(f"Missing required environment variable: {name}")
    return value


def main() -> int:
    formats = [f.strip() for f in os.environ.get("FORMATS", "").split(',') if f.strip()]
    cmd = [
        "intellisa",
        "--path", _get_env("INPUT_PATH"),
        "--tech", _get_env("INPUT_TECH"),
        "--postfilter", _get_env("INPUT_POSTFILTER"),
        "--out", _get_env("INPUT_SARIF_OUT"),
    ]
    for fmt in formats:
        cmd.extend(["--format", fmt])

    print("Running:", " ".join(shlex.quote(part) for part in cmd))
    result = subprocess.call(cmd)
    return result


if __name__ == "__main__":
    exit_code = main()
    if exit_code not in (0, 1):
        sys.exit(exit_code)
