"""Guard: ``_license_core.py`` is vendored byte-for-byte from oubliette-commerce
(``src/oubliette_commerce/_license_core.py``, the canonical copy). This pin
changes only on purpose: edit the canonical copy, copy it verbatim into
Shield, Trap and Dungeon, and update this hash in all four repos.
"""

import hashlib
from pathlib import Path

from oubliette_dungeon import _license_core

LICENSE_CORE_SHA256 = "5131cbdec0233a1289be97f7bbd146cac56a406558a9b437c1b1251f3a650dd4"


def test_license_core_matches_pinned_hash():
    core = Path(_license_core.__file__)
    assert hashlib.sha256(core.read_bytes()).hexdigest() == LICENSE_CORE_SHA256
