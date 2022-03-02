#!/usr/bin/env python

# Copyright 2012 - 2023, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A simplified version of client_exmample.py from the Python implementation:
# https://github.com/theupdateframework/python-tuf/blob/v1.0.0/examples/client_example/client_example.py

import argparse

from typing import List
from pathlib import Path

import tuf.api

from tuf.ngclient import Updater


def update_client(repo: str, targets: List[str]):
    metadata_dir = Path("tufrepo/metadata/current")
    targets_dir = Path("tuftargets")
    targets_dir.mkdir()
    updater = Updater(
        metadata_dir=str(metadata_dir),
        metadata_base_url=f"{repo}/repository/",
        target_base_url=f"{repo}/repository/targets/",
        target_dir=str(targets_dir),
    )

    updater.refresh()
    for target in targets:
        info = updater.get_targetinfo(target)
        assert not updater.find_cached_target(info)
        updater.download_target(info)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Retrieve file from TUF repository.")

    parser.add_argument(
        "-r",
        "--repo",
        type=str,
        required=True,
        metavar="<URI>",
        help="Specify the remote repository's URI"
        " (e.g., http://www.example.com:8001/tuf/).  The client retrieves"
        " updates from the remote repository.",
    )

    parser.add_argument(
        "targets",
        nargs="+",
        metavar="<file>",
        help="Specify"
        " the target files to retrieve from the specified TUF repository.",
    )

    parsed_arguments = parser.parse_args()
    return parsed_arguments


def main():
    arguments = parse_arguments()
    update_client(arguments.repo, arguments.targets)


if __name__ == "__main__":
    main()
