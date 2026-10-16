"""Fail early when the external wifi overlay no longer matches its stock base.

This guard belongs to the external development overlay. A native upstream
installation uses its own wifi module and does not need an overlay check.
"""

from functools import lru_cache
import hashlib
import json
from pathlib import Path


@lru_cache(maxsize=4)
def overlay_mismatches(overlay: Path, builtin: Path) -> tuple[str, ...]:
    overlay, builtin = overlay.resolve(), builtin.resolve()
    if overlay == builtin:
        return ()
    manifest = json.loads((overlay / "UPSTREAM.json").read_text())
    expected = manifest["original_sha256"]
    mismatches = []
    for name, digest in sorted(expected.items()):
        path = builtin / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            mismatches.append(name)
    return tuple(mismatches)


def validate_overlay_base() -> None:
    import esphome
    import esphome.config_validation as cv

    overlay = Path(__file__).parent
    builtin = Path(esphome.__file__).parent / "components" / "wifi"
    try:
        mismatches = overlay_mismatches(overlay, builtin)
    except (OSError, ValueError, KeyError) as error:
        raise cv.Invalid("Cannot verify the external wifi overlay's ESPHome base") from error
    if mismatches:
        raise cv.Invalid(
            "The external wifi overlay does not match this ESPHome installation "
            f"({', '.join(mismatches)}). Update and verify the overlay before compiling."
        )
