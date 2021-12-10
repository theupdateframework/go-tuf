package roles

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTopLevelRole(t *testing.T) {
	assert.True(t, IsTopLevelRole("root"))
	assert.True(t, IsTopLevelRole("targets"))
	assert.True(t, IsTopLevelRole("timestamp"))
	assert.True(t, IsTopLevelRole("snapshot"))
	assert.False(t, IsTopLevelRole("bins"))
}

func TestIsDelegatedTargetsRole(t *testing.T) {
	assert.False(t, IsDelegatedTargetsRole("root"))
	assert.False(t, IsDelegatedTargetsRole("targets"))
	assert.False(t, IsDelegatedTargetsRole("timestamp"))
	assert.False(t, IsDelegatedTargetsRole("snapshot"))
	assert.True(t, IsDelegatedTargetsRole("deleg"))
}

func TestIsTopLevelManifest(t *testing.T) {
	assert.True(t, IsTopLevelManifest("root.json"))
	assert.True(t, IsTopLevelManifest("targets.json"))
	assert.True(t, IsTopLevelManifest("timestamp.json"))
	assert.True(t, IsTopLevelManifest("snapshot.json"))
	assert.False(t, IsTopLevelManifest("bins.json"))
}

func TestIsDelegatedTargetsManifest(t *testing.T) {
	assert.False(t, IsDelegatedTargetsManifest("root.json"))
	assert.False(t, IsDelegatedTargetsManifest("targets.json"))
	assert.False(t, IsDelegatedTargetsManifest("timestamp.json"))
	assert.False(t, IsDelegatedTargetsManifest("snapshot.json"))
	assert.True(t, IsDelegatedTargetsManifest("bins.json"))
}

func TestIsVersionedManifest(t *testing.T) {
	assert.False(t, IsVersionedManifest("a.b"))
	assert.False(t, IsVersionedManifest("a.b.c"))
	assert.False(t, IsVersionedManifest("a.b.json"))
	assert.False(t, IsVersionedManifest("1.a"))
	assert.True(t, IsVersionedManifest("1.a.json"))
	assert.True(t, IsVersionedManifest("2.a.json"))
}
