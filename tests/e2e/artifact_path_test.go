package e2e

import (
	"path/filepath"
	"testing"
)

func TestArtifactBase(t *testing.T) {
	repo := filepath.Join(string(filepath.Separator), "workspace", "mongosniffer")
	if got, want := artifactBase(repo, filepath.Join(".artifacts", "e2e", "mongo-7")), filepath.Join(repo, ".artifacts", "e2e", "mongo-7"); got != want {
		t.Fatalf("artifactBase() = %q, want %q", got, want)
	}
	absolute := filepath.Join(t.TempDir(), "e2e")
	if got := artifactBase(repo, absolute); got != absolute {
		t.Fatalf("absolute artifact path = %q", got)
	}
}
