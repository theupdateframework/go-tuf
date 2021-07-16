package client

import (
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

// getTargetFileMeta searches for a verified TargetFileMeta matching a file name
// Requires a local snapshot to be loaded and is locked to the snapshot versions.
// Searches through delegated targets following TUF spec 1.0.19 section 5.6.
func (c *Client) getTargetFileMeta(file string) (data.TargetFileMeta, error) {
	snapshot, err := c.loadLocalSnapshot()
	if err != nil {
		return data.TargetFileMeta{}, err
	}

	// verifiers is map of parent targets name to an associated DelegationsVerifier
	// that can verify all child targets pointed by delegatedRoles in the parent targets
	verifiers := make(map[string]verify.DelegationsVerifier)

	// delegationsIterator covers 5.6.7
	// - pre-order depth-first search starting with the top targets
	// - filter delegations with paths or path_hash_prefixes matching searched file
	// - 5.6.7.1 cycles protection
	// - 5.6.7.2 terminations
	delegations := newDelegationsIterator(file)
	for i := 0; i < c.MaxDelegations; i++ {
		d, ok := delegations.next()
		if !ok {
			return data.TargetFileMeta{}, ErrUnknownTarget{file, snapshot.Version}
		}

		// covers 5.6.{1,2,3,4,5,6}
		verifier := verifiers[d.parent]
		target, err := c.loadDelegatedTargets(snapshot, d.child.Name, verifier)
		if err != nil {
			return data.TargetFileMeta{}, err
		}

		// stop when the searched TargetFileMeta is found
		if m, ok := target.Targets[file]; ok {
			return m, nil
		}

		if target.Delegations != nil {
			err := delegations.add(target.Delegations.Roles, d.child.Name)
			if err != nil {
				return data.TargetFileMeta{}, err
			}

			targetVerifier, err := verify.NewDelegationsVerifier(target.Delegations)
			if err != nil {
				return data.TargetFileMeta{}, err
			}
			verifiers[d.child.Name] = targetVerifier
		}
	}

	return data.TargetFileMeta{}, ErrMaxDelegations{
		File:            file,
		MaxDelegations:  c.MaxDelegations,
		SnapshotVersion: snapshot.Version,
	}
}

func (c *Client) loadLocalSnapshot() (*data.Snapshot, error) {
	if err := c.getLocalMeta(); err != nil {
		return nil, err
	}

	rawS, ok := c.localMeta["snapshot.json"]
	if !ok {
		return nil, ErrNoLocalSnapshot
	}

	snapshot := &data.Snapshot{}
	if err := c.db.Unmarshal(rawS, snapshot, "snapshot", c.snapshotVer); err != nil {
		return nil, ErrDecodeFailed{"snapshot.json", err}
	}
	return snapshot, nil
}

// loadDelegatedTargets downloads, decodes, verifies and stores targets
func (c *Client) loadDelegatedTargets(snapshot *data.Snapshot, role string, verifier verify.DelegationsVerifier) (*data.Targets, error) {
	var err error
	fileName := role + ".json"
	fileMeta, ok := snapshot.Meta[fileName]
	if !ok {
		return nil, ErrRoleNotInSnapshot{role, snapshot.Version}
	}

	// 5.6.1 download target if not in the local store
	// 5.6.2 check against snapshot hash
	raw, alreadyStored := c.localMetaFromSnapshot(fileName, fileMeta)
	if !alreadyStored {
		raw, err = c.downloadMetaFromSnapshot(fileName, fileMeta)
		if err != nil {
			return nil, err
		}
	}

	target := &data.Targets{}
	// 5.6.3 verify signature with parent public keys
	// 5.6.5 verify that the targets is not expired
	// role "targets" is the topTargets verified by root roles loaded in the client db
	if role == "targets" {
		err = c.db.Unmarshal(raw, target, role, fileMeta.Version)
	} else {
		err = verifier.Unmarshal(raw, target, role, fileMeta.Version)
	}
	if err != nil {
		return nil, ErrDecodeFailed{fileName, err}
	}

	// 5.6.4 check against snapshot version
	if target.Version != fileMeta.Version {
		return nil, ErrTargetsSnapshotVersionMismatch{
			Role:                     fileName,
			DownloadedTargetsVersion: fileMeta.Version,
			TargetsSnapshotVersion:   target.Version,
			SnapshotVersion:          snapshot.Version,
		}
	}
	// 5.6.6 persist
	if !alreadyStored {
		if err := c.local.SetMeta(fileName, raw); err != nil {
			return nil, err
		}
	}
	return target, nil
}

type delegation struct {
	parent string
	child  data.DelegatedRole
}

type delegationID struct {
	parent string
	child  string
}

type delegationsIterator struct {
	stack   []delegation
	file    string
	visited map[delegationID]struct{}
}

// newDelegationsIterator initialises an iterator with a first step
// on top level targets
func newDelegationsIterator(file string) *delegationsIterator {
	i := &delegationsIterator{
		file: file,
		stack: []delegation{
			{
				child: data.DelegatedRole{Name: "targets"},
			},
		},
		visited: make(map[delegationID]struct{}),
	}
	return i
}

func (d *delegationsIterator) next() (delegation, bool) {
	if len(d.stack) == 0 {
		return delegation{}, false
	}
	delegation := d.stack[len(d.stack)-1]
	d.stack = d.stack[:len(d.stack)-1]

	// 5.6.7.1 cycles protection
	id := delegationID{delegation.parent, delegation.child.Name}
	if _, ok := d.visited[id]; ok {
		return d.next()
	}
	d.visited[id] = struct{}{}

	// 5.6.7.2 trim delegations to visit, only the current role and its delegations
	// will be considered
	// https://github.com/theupdateframework/specification/issues/168
	if delegation.child.Terminating {
		d.stack = d.stack[0:0]
	}
	return delegation, true
}

func (d *delegationsIterator) add(roles []data.DelegatedRole, parent string) error {
	for i := len(roles) - 1; i >= 0; i-- {
		// Push the roles onto the stack in reverse so we get an in-order traversal
		// of the delegations graph.
		r := roles[i]
		matchesPath, err := r.MatchesPath(d.file)
		if err != nil {
			return err
		}
		if matchesPath {
			d.stack = append(d.stack, delegation{parent, r})
		}
	}

	return nil
}
