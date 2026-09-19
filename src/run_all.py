"""Run all six MCP server examples back to back.

    python src/run_all.py

Reading the output top to bottom is the point: the same policy table and the
same primitives, gated by six different authentication mechanisms. Watch what
each server is able to learn about the caller -- and which user-scoped calls it
therefore has to deny.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Ordered so each mechanism builds on the previous one -- DPoP directly follows
# the OAuth it upgrades, rather than sorting by folder number.
EXAMPLES = [
    ("01-api-keys", None),
    ("02-oauth-oidc", None),
    ("06-oauth-dpop", "cryptography"),
    ("03-mtls", None),
    ("04-spiffe-spire", None),
    ("05-aauth", "cryptography"),
]


def main() -> int:
    failures = []
    for folder, requirement in EXAMPLES:
        if requirement:
            try:
                __import__(requirement)
            except ImportError:
                print(f"\n!! skipping {folder}: needs `pip install {requirement}`")
                continue

        result = subprocess.run([sys.executable, os.path.join(HERE, folder, "server.py")])
        if result.returncode != 0:
            failures.append(folder)

    if failures:
        print(f"\nFAILED: {', '.join(failures)}")
        return 1

    print("\n" + "=" * 74)
    print("  All examples ran. See src/README.md for what separates them.")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
