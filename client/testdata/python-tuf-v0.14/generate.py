#!/usr/bin/env python3
#
# A script to generate TUF repository files.

import datetime
import json
import os.path
import shutil
import sys

import securesystemslib.keys
import securesystemslib.util
import tuf.repository_tool

REPOSITORY_NAME = 'test'

def load_role_keys():
    new_role_keys = {}

    with open('../keys.json') as f:
        role_keys = json.load(f)

    # Convert the key into a python-tuf private keys.
    for role, keysets in role_keys.items():
        new_keysets = []

        for keys in keysets:
            new_keys = []

            for key in keys:
                # If the key is ed25519, the `private` field is a 128 character
                # string, where the first 64 characters are the private key, and
                # the second 64 characters is the public key. python-tuf only wants
                # the private key, so extract that from the value.
                private_key = key['keyval']['private']
                if key['keytype'] == 'ed25519':
                    assert private_key[64:] == key['keyval']['public']
                    private_key = private_key[:64]

                private, junk = securesystemslib.keys.format_metadata_to_key({
                    'keytype': key['keytype'],
                    'scheme': key['scheme'],
                    'keyval': {
                        'public': key['keyval']['public'],
                        'private': private_key,
                    },
                })

                new_keys.append(private)

            new_keysets.append(new_keys)

        new_role_keys[role] = new_keysets

    return new_role_keys


def new_repo(repo_dir):
    repository = tuf.repository_tool.create_new_repository(repo_dir, repository_name=REPOSITORY_NAME)
    repository.targets.compressions = ['gz']

    return repository


def load_repo(repo_dir, role_keys):
    repo = tuf.repository_tool.load_repository(repo_dir, repository_name=REPOSITORY_NAME)

    for role, keys in role_keys.items():
        metadata = get_metadata_for_role(repo, role)

        for key in keys:
            metadata.load_signing_key(key)

    return repo


def get_metadata_for_role(repository, role):
    if role == 'root':
        return repository.root
    elif role == 'targets':
        return repository.targets
    elif role == 'snapshot':
        return repository.snapshot
    elif role == 'timestamp':
        return repository.timestamp
    else:
        raise 'No metadata found for role %r' % role


def add_keys(repository, role_keys):
    for role, keys in role_keys.items():
        for key in keys:
            metadata = get_metadata_for_role(repository, role)

            # Convert the key into a python-tuf public key.
            metadata.add_verification_key(key)
            metadata.load_signing_key(key)
            metadata.expiration = datetime.datetime(2100, 1, 1, 0, 0)


def revoke_keys(repository, role, keys):
    for key in keys:
        metadata = get_metadata_for_role(repository, role)
        metadata.remove_verification_key(key)


def add_targets(repository, repo_dir, targets):
    targets_dir = os.path.join(repo_dir, 'targets')

    for filename, data in targets.items():
        filepath = os.path.join(targets_dir, filename)
        securesystemslib.util.ensure_parent_dir(filepath)

        with open(filepath, 'wt') as file_object:
          file_object.write(data['contents'])

        # python-tuf expects target paths to be in the targets directory.
        target_path = os.path.relpath(filepath, targets_dir)

        repository.targets.add_target(target_path, data.get('custom'))


def commit(repository, repo_dir, consistent_snapshot):
    repository.writeall(consistent_snapshot=consistent_snapshot)

    staged_meta_directory = os.path.join(repo_dir, 'metadata.staged')
    live_meta_directory = os.path.join(repo_dir, 'metadata')

    shutil.rmtree(live_meta_directory, ignore_errors=True)
    shutil.copytree(staged_meta_directory, live_meta_directory)

    tuf.roledb.remove_roledb(REPOSITORY_NAME)
    tuf.keydb.remove_keydb(REPOSITORY_NAME)


def generate_repos(root_dir, consistent_snapshot):
    role_keys = load_role_keys()

    keys = {
        'root':      role_keys['root'][0],
        'targets':   role_keys['targets'][0],
        'snapshot':  role_keys['snapshot'][0],
        'timestamp': role_keys['timestamp'][0],
    }

    # Create the initial repo.
    dir0 = os.path.join(root_dir, '0')
    repo_dir0 = os.path.join(dir0, 'repository')

    repo0 = new_repo(repo_dir0)
    add_keys(repo0, keys)
    add_targets(repo0, repo_dir0, { '0': { 'contents': '0' } })
    commit(repo0, repo_dir0, consistent_snapshot)

    # Rotate all the keys to make sure that it works.
    old_dir = dir0
    i = 1

    for role in ["root", "targets", "snapshot", "timestamp"]:
        step_name = str(i)
        d = os.path.join(root_dir, step_name)
        shutil.copytree(old_dir, d)
        repo_dir = os.path.join(d, 'repository')

        repo1 = load_repo(repo_dir, keys)
        revoke_keys(repo1, role, role_keys[role][0])
        add_keys(repo0, {
            role: role_keys[role][1],
        })
        keys[role] = role_keys[role][1]
        add_targets(repo1, repo_dir, { step_name: { 'contents': step_name } })
        commit(repo1, repo_dir, consistent_snapshot)

        i += 1
        old_dir = d

    # Add another target file to make sure the workflow worked.
    step_name = str(i)
    d = os.path.join(root_dir, step_name)
    shutil.copytree(old_dir, d)
    repo_dir = os.path.join(d, 'repository')

    repo = load_repo(repo_dir, keys)
    add_targets(repo, repo_dir, { step_name: { 'contents': step_name } })
    commit(repo, repo_dir, consistent_snapshot)


def main():
    generate_repos("consistent-snapshot-false", False)
    generate_repos("consistent-snapshot-true", True)


if __name__ == '__main__':
    sys.exit(main())
