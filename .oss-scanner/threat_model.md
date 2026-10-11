# go-tuf OSS Scanner threat model

## Project and security goals

go-tuf is a Go implementation of The Update Framework (TUF). It is used to
create, parse, sign, verify, and consume TUF metadata, including in client
update workflows. Its primary security goal is to ensure that a client only
accepts metadata and target files authorized by its configured trusted root
metadata and the TUF specification's verification rules.

High-impact failures include accepting a malicious or unauthorized target,
trusting metadata without the required valid signatures, or bypassing
integrity, rollback, expiry, or delegation checks. The library is also expected
to reject malformed or inconsistent untrusted metadata without crashing,
panicking, or consuming unbounded resources.

## Untrusted inputs

Treat all of the following as adversarial unless explicitly established as a
trusted local root of trust by the caller:

- Root, timestamp, snapshot, targets, and delegated-targets metadata supplied
  by a repository or network fetcher.
- Metadata signatures, keys, role definitions, version numbers, expiry times,
  hashes, lengths, delegation paths, and path hash prefixes.
- Target file names, target data, and target metadata downloaded through the
  updater and multi-repository client APIs.
- Multi-repository configuration and mapping data that controls which
  repositories and roots of trust participate in a target lookup.

## In scope

Focus review on defects that could affect client security, especially:

- Metadata parsing and canonical serialization that changes the bytes covered
  by signatures or mishandles unrecognized fields.
- Signature, key type, threshold, and role authorization verification.
- Root rotation and trusted-root update rules.
- Version, rollback, freeze/expiry, hash, length, and consistent-snapshot
  enforcement.
- Target and delegation selection, including path and path-hash-prefix
  matching, terminating delegations, and succinct hash-bin delegations.
- Updater, fetcher, and multi-repository behavior that could let untrusted
  data select an unexpected repository, root of trust, metadata file, or
  target.
- Panics, denial of service, resource exhaustion, or path traversal reachable
  from malformed metadata or targets.

## Out of scope

The availability or compromise of a repository, signing key, transport, or
caller-provided fetcher is not itself a vulnerability when the library applies
its documented TUF verification rules correctly. The application integrating
go-tuf is responsible for securely provisioning its initial trusted root,
choosing its fetcher and local storage, and enforcing its own authorization
policy for target use.

## Severity and report guidance

Report issues with a minimal, self-contained reproducer that identifies the
affected go-tuf version or commit and demonstrates the security impact. Give
highest severity to issues that let an attacker who controls repository content
or network-delivered metadata cause a client to accept an unauthorized target
or metadata, bypass required signatures or integrity checks, or replace a
trusted root outside the TUF update rules. Include proposed patches when
available, but do not publicly disclose candidate vulnerabilities.
