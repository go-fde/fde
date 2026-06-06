package fde

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpen_InvalidType covers the Open default branch: an unknown Type
// value should return an "unknown type" error.
func TestOpen_InvalidType(t *testing.T) {
	if _, err := Open(Type(99), "/dev/null", nil); err == nil {
		t.Fatal("expected error for invalid Type")
	}
}

// fdeMemRW is a minimal in-memory RW satisfying fde.RW for OpenFrom tests.
type fdeMemRW struct{}

func (*fdeMemRW) ReadAt(p []byte, off int64) (int, error)  { return len(p), nil }
func (*fdeMemRW) WriteAt(p []byte, off int64) (int, error) { return len(p), nil }
func (*fdeMemRW) Close() error                             { return nil }

// TestOpenFrom_InvalidType covers the OpenFrom default branch.
func TestOpenFrom_InvalidType(t *testing.T) {
	if _, err := OpenFrom(Type(99), &fdeMemRW{}, nil); err == nil {
		t.Fatal("expected error for invalid Type")
	}
}

// TestOpenFrom_LUKS_ExplicitKind exercises the OpenFrom switch case for
// LUKS when caller supplies the kind directly (no Auto detection).
func TestOpenFrom_LUKS_ExplicitKind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	pass := []byte("explicit-kind-luks")
	fdeBuildLUKS1ImageFile(t, path, pass, fdeRand(32))
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenFrom(LUKS, f, pass)
	if err != nil {
		f.Close()
		t.Fatalf("OpenFrom(LUKS): %v", err)
	}
	dev.Close()
}

// TestOpenFrom_APFS_ExplicitKind exercises the OpenFrom switch case for
// APFS when caller supplies the kind directly.
func TestOpenFrom_APFS_ExplicitKind(t *testing.T) {
	passphrase := []byte("explicit-kind-apfs")
	img := fdeBuildRawAPFSImage(t, passphrase, make([]byte, apfsTestSectorSz))
	path := filepath.Join(t.TempDir(), "apfs.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenFrom(APFS, f, passphrase)
	if err != nil {
		f.Close()
		t.Fatalf("OpenFrom(APFS): %v", err)
	}
	dev.Close()
}

// TestOpenFrom_CLEAR_ExplicitKind exercises the OpenFrom switch case for
// CLEAR when caller supplies the kind directly.
func TestOpenFrom_CLEAR_ExplicitKind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.bin")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenFrom(CLEAR, f, nil)
	if err != nil {
		f.Close()
		t.Fatalf("OpenFrom(CLEAR): %v", err)
	}
	dev.Close()
}
