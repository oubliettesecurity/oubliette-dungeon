"""Single source of the runtime package version.

Must equal ``[project].version`` in pyproject.toml; enforced by
``tests/unit/test_version_sync.py``. Lives in its own module so submodules
(CLI, API, report/OSEF writers) can import it without a circular import
through ``oubliette_dungeon/__init__.py``.
"""

__version__ = "1.0.3"
