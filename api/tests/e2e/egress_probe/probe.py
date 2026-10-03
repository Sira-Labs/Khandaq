"""Test-only adapter: tries to reach the in-scope target and hosts it must NOT reach, records what
happened, and emits the adapter output contract (a tar of /evidence on stdout; spec 012)."""

import json
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

request = json.loads(os.environ["KHANDAQ_RUN_REQUEST"])
attempts = {
    "target": request["target"]["spec"]["base_url"].rsplit("/v1", 1)[0] + "/health",
    **request["params"]["must_not_reach"],
}
results = {}
for name, url in attempts.items():
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            results[name] = {"ok": True, "status": resp.status, "body": resp.read(200).decode()}
    except (OSError, ValueError) as exc:
        results[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
# The adapter user must not be root, and the rootfs must be read-only.
results["uid"] = os.getuid()
try:
    Path("/probe-write-test").write_text("x")
    results["rootfs_writable"] = True
except OSError:
    results["rootfs_writable"] = False
print(json.dumps(results), file=sys.stderr)

evidence = Path("/evidence")
(evidence / "results.json").write_text(json.dumps(results))
(evidence / "findings.jsonl").write_text("")
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as tar:
    for path in sorted(evidence.iterdir()):
        tar.add(path, arcname=path.name)
