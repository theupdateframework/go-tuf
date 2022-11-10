#!/usr/bin/env python
#
# A script to generate TUF repository files.
#
# A modification of generate.py from the Python implementation:
# https://github.com/theupdateframework/tuf/blob/v0.9.9/tests/repository_data/generate.py
# Updated a bit for the v1.0.0 version:
# https://github.com/theupdateframework/python-tuf/blob/v1.0.0/examples/repo_example/basic_repo.py

import datetime
import optparse
import shutil

from pathlib import Path
from typing import Dict

import securesystemslib.util

from securesystemslib.keys import generate_ed25519_key
from securesystemslib.signer import SSlibSigner
from tuf.api.metadata import (
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer


SPEC_VERSION = "1.0.19"
PRETTY = JSONSerializer(compact=False)
EXPIRY = datetime.datetime(2030, 1, 1, 0, 0)  # Far enough in the future
ROLES = set(("targets", "snapshot", "timestamp", "root"))


def make_targets(target_dir: Path, consistent_snapshot: bool) -> Dict[str, TargetFile]:
    targets = {}
    for target in (Path("file1.txt"), Path("dir/file2.txt")):
        target_fspath = target_dir / target
        target_fspath.parent.mkdir(parents=True, exist_ok=True)
        target_fspath.write_text(target.name)  # file contents are the file name
        target_file_info = TargetFile.from_file(str(target), str(target_fspath))
        if consistent_snapshot:
            digest = next(iter(target_file_info.hashes.values()))
            shutil.move(target_fspath, target_fspath.parent / f"{digest}.{target.name}")
        targets[str(target)] = target_file_info
    return targets


def make_test_repo(repo_dir: Path, consistent_snapshot: bool):
    """Create a test repository in `repo_dir`.

    Two targets:
    - `file1.txt`
    - `dir/file2.txt`
    """
    roles: Dict[str, Metadata] = {}

    targets: Dict[str, TargetFile] = {}
    target_dir = repo_dir / "targets"
    target_dir.mkdir()
    targets = make_targets(target_dir, consistent_snapshot)
    target_metadata = Targets(
        version=1, spec_version=SPEC_VERSION, expires=EXPIRY, targets=targets
    )
    roles["targets"] = Metadata[Targets](target_metadata, {})

    snapshot_metadata = Snapshot(
        version=1,
        spec_version=SPEC_VERSION,
        expires=EXPIRY,
        meta={"targets.json": MetaFile(version=1)},
    )
    roles["snapshot"] = Metadata[Snapshot](snapshot_metadata, {})

    timestamp_metadata = Timestamp(
        version=1,
        spec_version=SPEC_VERSION,
        expires=EXPIRY,
        snapshot_meta=MetaFile(version=1),
    )
    roles["timestamp"] = Metadata[Timestamp](timestamp_metadata, {})

    keys = {name: generate_ed25519_key() for name in ROLES}

    root_metadata = Root(
        version=1,
        spec_version=SPEC_VERSION,
        expires=EXPIRY,
        keys={
            key["keyid"]: Key.from_securesystemslib_key(key) for key in keys.values()
        },
        roles={role: Role([key["keyid"]], threshold=1) for role, key in keys.items()},
        consistent_snapshot=consistent_snapshot,
    )
    roles["root"] = Metadata[Root](root_metadata, {})

    # Write the metadata files
    metadata_dir = repo_dir / "metadata"
    metadata_dir.mkdir()
    for name in ["root", "targets", "snapshot", "timestamp"]:
        role = roles[name]
        key = keys[role.signed.type]
        signer = SSlibSigner(key)
        role.sign(signer)

        if name == "root" or (consistent_snapshot and name != "timestamp"):
            filename = f"{role.signed.version}.{name}.json"
        else:
            filename = f"{name}.json"
        role.to_file(str(metadata_dir / filename), serializer=PRETTY)


def main():
    parser = optparse.OptionParser()
    parser.add_option(
        "-c",
        "--consistent-snapshot",
        action="store_true",
        dest="consistent_snapshot",
        help="Generate consistent snapshot",
        default=False,
    )
    (options, args) = parser.parse_args()

    repo_dir = Path("repository")
    repo_dir.mkdir()
    make_test_repo(repo_dir, options.consistent_snapshot)


if __name__ == "__main__":
    main()
