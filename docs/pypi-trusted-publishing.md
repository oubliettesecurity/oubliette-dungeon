# PyPI Trusted Publishing (OIDC)

`oubliette-dungeon` publishes to PyPI from this repo
(`oubliettesecurity/oubliette-dungeon`) via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — no API token
is stored in GitHub secrets. The workflow is `.github/workflows/publish.yml`.

## One-time setup on pypi.org (maintainer must do this)

Do **not** expect CI to configure PyPI. Before the first tag is pushed, a
maintainer must add the Trusted Publisher once:

1. Sign in at [pypi.org](https://pypi.org) as a maintainer of **oubliette-dungeon**.
2. Open **Publishing**:
   https://pypi.org/manage/project/oubliette-dungeon/settings/publishing/
3. Under **Add a new publisher** → **GitHub**, set:

   | Field | Value |
   |---|---|
   | Owner | `oubliettesecurity` |
   | Repository name | `oubliette-dungeon` |
   | Workflow name | `publish.yml` |
   | Environment name | `pypi` |

4. Save. If an older publisher entry exists for `release.yml` (the previous
   workflow, whose OIDC exchange never succeeded), remove it.

## Matching GitHub Environment

This repo has a GitHub Environment named **`pypi`**. The publish job uses
`environment: pypi` so the OIDC claims match the publisher above. Optional:
add required reviewers or a wait timer for production publishes.

## Tag-and-release flow

1. Bump `version` in `pyproject.toml` and `__version__` in
   `src/oubliette_dungeon/_version.py` (`tests/unit/test_version_sync.py`
   fails if they differ), update `CHANGELOG.md`, and merge to `main`.
   Do **not** publish from an untagged commit.
2. Tag the release commit and push the tag:

   ```bash
   git tag vX.Y.Z <commit>
   git push origin vX.Y.Z
   ```

   The workflow triggers only on `v[0-9]*.[0-9]*.[0-9]*` tags. The moving
   `v1` tag used by consumers of the GitHub Action (`uses:
   oubliettesecurity/oubliette-dungeon@v1`) does **not** trigger a publish.
3. `Publish to PyPI` checks that the tag equals `v` + the pyproject version,
   builds sdist + wheel with uv (Python 3.13), runs `twine check`, runs
   `tests/unit/test_packaging_boundary.py` against the built files (fail
   closed), uploads with PEP 740 attestations and `skip-existing: true`, and
   creates/updates the GitHub Release with the dist files attached.

Manual re-run: **Actions → Publish to PyPI → Run workflow**, enter an existing
tag (e.g. `v1.0.3`). Set **dry_run** to build + gate only (no upload, no
GitHub Release).

## Packaging boundary

The wheel may contain only `oubliette_dungeon/` and its `.dist-info`; the
sdist only `src/oubliette_dungeon/`, its egg-info, and `LICENSE`,
`README.md`, `pyproject.toml`, `setup.cfg`, `PKG-INFO`. Anything else
(`tests/`, `reports/`, `benchmarks/`, `scripts/`, `contrib/`, `docker/`,
`dashboard/`, `.env`, keys) fails the gate. The CI `build` job runs the same
check on every PR.
