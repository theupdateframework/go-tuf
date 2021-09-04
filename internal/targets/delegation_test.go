package targets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

var (
	defaultPathPatterns = []string{"tmp", "*"}
	noMatchPathPatterns = []string{"vars", "null"}
)

func TestDelegationsIterator(t *testing.T) {
	var iteratorTests = []struct {
		testName    string
		roles       map[string][]data.DelegatedRole
		file        string
		resultOrder []string
		err         error
	}{
		{
			testName: "no termination",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns},
				},
				"c": {
					{Name: "d", Paths: defaultPathPatterns},
				},
				"e": {
					{Name: "f", Paths: defaultPathPatterns},
					{Name: "g", Paths: defaultPathPatterns},
				},
				"g": {
					{Name: "h", Paths: defaultPathPatterns},
					{Name: "i", Paths: defaultPathPatterns},
					{Name: "j", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
		},
		{
			testName: "terminated in b",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, Terminating: true},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns},
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c", "d"},
		},
		{
			testName: "path does not match b",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: noMatchPathPatterns},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns},
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "e"},
		},
		{
			testName: "path does not match b - path prefixes",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", PathHashPrefixes: []string{"33472a4909"}},
					{Name: "c", PathHashPrefixes: []string{"34c85d1ee84f61f10d7dc633"}},
				},
				"c": {
					{Name: "d", PathHashPrefixes: []string{"8baf"}},
					{Name: "e", PathHashPrefixes: []string{"34c85d1ee84f61f10d7dc633472a49096ed87f8f764bd597831eac371f40ac39"}},
				},
			},
			file:        "/e/f/g.txt",
			resultOrder: []string{"targets", "c", "e"},
		},
		{
			testName: "err paths and pathHashPrefixes are set",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, PathHashPrefixes: defaultPathPatterns},
				},
				"b": {},
			},
			file:        "",
			resultOrder: []string{"targets"},
			err:         data.ErrPathsAndPathHashesSet,
		},
		{
			testName: "cycle avoided 1",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "targets", Paths: defaultPathPatterns},
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "d", "e"},
		},
		{
			testName: "cycle avoided 2",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "targets", Paths: defaultPathPatterns},
					{Name: "b", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "targets", Paths: defaultPathPatterns},
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "c", Paths: defaultPathPatterns},
				},
				"c": {
					{Name: "c", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c"},
		},
		{
			testName: "diamond delegation",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "c", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "d", Paths: defaultPathPatterns},
				},
				"c": {
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "d", "c"},
		},
		{
			testName: "simple cycle",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "a", Paths: defaultPathPatterns},
				},
				"a": {
					{Name: "a", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "a"},
		},
	}

	for _, tt := range iteratorTests {
		t.Run(tt.testName, func(t *testing.T) {
			d := NewDelegationsIterator(tt.file)
			var iterationOrder []string
			for {
				r, ok := d.Next()
				if !ok {
					break
				}
				iterationOrder = append(iterationOrder, r.Delegatee.Name)
				delegations, ok := tt.roles[r.Delegatee.Name]
				if !ok {
					continue
				}
				err := d.Add(delegations, r.Delegatee.Name, verify.DelegationsVerifier{})
				assert.Equal(t, tt.err, err)
			}
			assert.Equal(t, tt.resultOrder, iterationOrder)
		})
	}
}
