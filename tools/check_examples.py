#!/usr/bin/env python3
"""Validate and generate pinned examples locally without accessing devices."""

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

import yaml
from esphome.const import __version__


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {
    "wifi_ssid": "synthetic-test-wifi",
    "wifi_password": "synthetic-wifi-password",
    "mesh_key": "00" * 32,
    "api_key": base64.b64encode(bytes(range(32))).decode(),
}


def main() -> None:
    if __version__ != "2026.9.1":
        raise SystemExit("Use ESPHome 2026.9.1: pip install -r requirements-test.txt")
    manifest = json.loads((ROOT / "SOURCE_MANIFEST.json").read_text())
    for name, expected in manifest["files"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise SystemExit(f"Source identity mismatch: {name}")
    with tempfile.TemporaryDirectory(prefix="esphome-mesh-examples-") as temporary:
        directory = Path(temporary)
        for name in ("wifi-node.yaml", "mesh-only-node.yaml", "ethernet-gateway.yaml"):
            text = (ROOT / "examples" / name).read_text()
            for key, value in FIXTURES.items():
                text = text.replace("!secret " + key, json.dumps(value))
            config = yaml.safe_load(text)
            config["external_components"][0]["source"] = {
                "type": "local", "path": str(ROOT / "components")
            }
            config["esphome"]["build_path"] = str(directory / (name + "-build"))
            path = directory / name
            path.write_text(yaml.safe_dump(config, sort_keys=False))
            for command in (["config", str(path)], ["compile", str(path), "--only-generate"]):
                result = subprocess.run(
                    [sys.executable, "-m", "esphome", *command],
                    capture_output=True, text=True, check=False,
                )
                if result.returncode:
                    print(result.stdout)
                    print(result.stderr, file=sys.stderr)
                    raise SystemExit(result.returncode)
            main_cpp = Path(config["esphome"]["build_path"]) / "src/main.cpp"
            if not main_cpp.is_file():
                raise SystemExit(f"Missing generated C++ for {name}")
            print(f"PASS {name}: validation and C++ generation; no build or device access")
    print(f"PASS source identities: {len(manifest['files'])} component files")


if __name__ == "__main__":
    main()
