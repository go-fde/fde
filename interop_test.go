package fde

// End-to-end interop tests that open real cryptsetup-created LUKS2 containers
// through the fde public API.
//
// These fixtures (testdata/cryptsetup_luks2_*.img.gz) were produced by the real
// cryptsetup 2.7.0 tool, which wrote a known plaintext marker at payload offset
// 0 through its dm-crypt mapping. fde must unlock the container itself (via
// go-fde/luks) and read that marker back byte-for-byte.
//
// This guards the anti-forensic (AF) diffusion regression end-to-end: LUKS AF
// diffuse is a plain, keyless HASH(BE32(i) || block), NOT HMAC. When the luks
// AF-merge does not match the algorithm real cryptsetup used to AF-split the
// key material, every keyslot is rejected with "no key slot matches
// passphrase" and these tests fail. They run in CI without cryptsetup because
// the containers are committed fixtures.

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// interopPassphrase is the passphrase the committed cryptsetup fixtures were
// created with.
const interopPassphrase = "hunter2pass"

// interopMarkerPrefix is the leading marker string cryptsetup wrote into each
// fixture's payload at offset 0.
const interopMarkerPrefix = "GOFDE-INTEROP-"

// decompressFixture expands a gzipped fixture to a temp file and returns its
// path.
func decompressFixture(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()
	out := filepath.Join(t.TempDir(), "container.img")
	w, err := os.Create(out)
	if err != nil {
		t.Fatalf("create temp container: %v", err)
	}
	if _, err := io.Copy(w, gr); err != nil {
		w.Close()
		t.Fatalf("decompress fixture: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close temp container: %v", err)
	}
	return out
}

// openCryptsetupFixtureThroughFDE opens a committed real-cryptsetup LUKS2
// container through the fde public API and asserts the plaintext marker
// cryptsetup wrote reads back exactly. It exercises both fde.OpenLUKS and the
// auto-detecting fde.Open(fde.Auto, …) path.
func openCryptsetupFixtureThroughFDE(t *testing.T, fixture, wantMarker string) {
	t.Helper()
	path := decompressFixture(t, fixture)

	read := func(dev Device) {
		defer dev.Close()
		buf := make([]byte, len(wantMarker))
		if _, err := dev.ReadAt(buf, 0); err != nil {
			t.Fatalf("ReadAt payload: %v", err)
		}
		if string(buf) != wantMarker {
			t.Fatalf("payload marker mismatch:\n got %q\nwant %q", buf, wantMarker)
		}
	}

	dev, err := OpenLUKS(path, []byte(interopPassphrase))
	if err != nil {
		t.Fatalf("OpenLUKS cryptsetup fixture %s: %v", fixture, err)
	}
	read(dev)

	autoDev, err := Open(Auto, path, []byte(interopPassphrase))
	if err != nil {
		t.Fatalf("Open(Auto) cryptsetup fixture %s: %v", fixture, err)
	}
	read(autoDev)
}

// TestInterop_CryptsetupDefault_LUKS2 opens a stock cryptsetup-default LUKS2
// container (argon2id KDF, aes-xts-plain64, 4000 AF stripes, sha256, 4096-byte
// sectors) through fde and verifies the cryptsetup-written marker.
func TestInterop_CryptsetupDefault_LUKS2(t *testing.T) {
	openCryptsetupFixtureThroughFDE(t,
		"cryptsetup_luks2_default.img.gz",
		interopMarkerPrefix+"def-PAYLOAD-0123456789ABCDEF")
}

// TestInterop_CryptsetupPBKDF2_LUKS2 opens a cryptsetup LUKS2 container created
// with `--pbkdf pbkdf2` (pbkdf2-sha256 keyslot) through fde and verifies the
// cryptsetup-written marker.
func TestInterop_CryptsetupPBKDF2_LUKS2(t *testing.T) {
	openCryptsetupFixtureThroughFDE(t,
		"cryptsetup_luks2_pbkdf2.img.gz",
		interopMarkerPrefix+"pb-PAYLOAD-0123456789ABCDEF")
}
