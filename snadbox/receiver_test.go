package snadbox

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSafeJoinAcceptsNestedPath(t *testing.T) {
	dir := t.TempDir()

	got, err := safeJoin(dir, "a/b/c.txt")
	if err != nil {
		t.Fatalf("safeJoin: %v", err)
	}

	want := filepath.Join(dir, "a", "b", "c.txt")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSafeJoinRejectsTraversal(t *testing.T) {
	dir := t.TempDir()

	cases := []string{
		"../../etc/passwd",
		"/etc/passwd",
		"a/../../b",
		"",
		".",
		`a\..\..\b`,
	}

	for _, rel := range cases {
		if _, err := safeJoin(dir, rel); err == nil {
			t.Errorf("safeJoin(%q): expected error, got none", rel)
		}
	}
}

func TestMapDirectoryWalksRecursivelyAndSkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on windows")
	}

	dir := t.TempDir()
	outside := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}

	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(dir, "evil")); err != nil {
		t.Fatal(err)
	}

	set, err := mapDirectory(dir)
	if err != nil {
		t.Fatalf("mapDirectory: %v", err)
	}

	want := []string{"a.txt", filepath.ToSlash(filepath.Join("sub", "b.txt"))}
	if len(want) != len(set) {
		t.Fatalf("got %d entries (%v) want %v", len(set), set, want)
	}
	for _, k := range want {
		if !set.Contains(k) {
			t.Fatalf("expected set to contain %q, got %v", k, set)
		}
	}
	if set.Contains("evil") {
		t.Fatalf("expected symlink %q to be excluded, got %v", "evil", set)
	}
}
