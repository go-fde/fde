package fde

// Regression tests for go-fde/fde#41: the facade passes one key-derivation
// budget (go-encryptions/kdfbudget) to the LUKS and APFS backends, and caps
// APFS Argon2 threads, so a hostile header cannot make one unlock do more than
// the caller allows.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/go-encryptions/kdfbudget"
	apfsfde "github.com/go-fde/apfs"
	"github.com/go-fde/luks"
)

// hostileLUKS2 returns the path of the cryptsetup PBKDF2 fixture whose key slot
// and digest ask for iterations PBKDF2 rounds. Every header copy gets its
// checksum recomputed, so the header is valid and only the cost is hostile.
func hostileLUKS2(t *testing.T, iterations string) string {
	t.Helper()
	path := decompressFixture(t, "cryptsetup_luks2_pbkdf2.img.gz")
	img, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hdrSize := int(binary.BigEndian.Uint64(img[8:16]))
	re := regexp.MustCompile(`"iterations":\d+`)
	for _, off := range []int{0, hdrSize} {
		hdr := img[off : off+hdrSize]
		area := hdr[4096:]
		end := bytes.IndexByte(area, 0)
		if end < 0 {
			t.Fatal("no NUL after the JSON area")
		}
		js := re.ReplaceAll(area[:end], []byte(`"iterations":`+iterations))
		if len(js) > len(area) {
			t.Fatalf("patched JSON of %d bytes does not fit %d", len(js), len(area))
		}
		clear(area)
		copy(area, js)
		clear(hdr[448:512])
		sum := sha256.Sum256(hdr)
		copy(hdr[448:], sum[:])
	}
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOpenLUKS_HostileHeaderRefusedByCallerBudget: a header within the
// backend's structural limits that asks for 5e7 PBKDF2 rounds is refused with
// ErrLimit under a caller's budget, before any derivation runs.
func TestOpenLUKS_HostileHeaderRefusedByCallerBudget(t *testing.T) {
	path := hostileLUKS2(t, "50000000")
	b := kdfbudget.Unlimited()
	b.MaxWork = 1 << 20
	for name, open := range map[string]func() (Device, error){
		"OpenLUKS": func() (Device, error) { return OpenLUKS(path, []byte(interopPassphrase), WithBudget(b)) },
		"Open": func() (Device, error) {
			return Open(LUKS, path, []byte(interopPassphrase), WithBudget(b))
		},
	} {
		dev, err := open()
		if err == nil {
			dev.Close()
			t.Fatalf("%s: a hostile header opened under a budget of %d units", name, b.MaxWork)
		}
		if !errors.Is(err, kdfbudget.ErrLimit) || !errors.Is(err, luks.ErrLimit) {
			t.Errorf("%s: err = %v, want ErrLimit", name, err)
		}
	}
	if got := b.Spent(); got != 0 {
		t.Errorf("a refused charge spent %d units", got)
	}
}

// TestOpenLUKS_SharedBudgetIsDrained: one budget handed to two unlocks caps
// their sum.
func TestOpenLUKS_SharedBudgetIsDrained(t *testing.T) {
	path := decompressFixture(t, "cryptsetup_luks2_pbkdf2.img.gz")
	probe := kdfbudget.Unlimited()
	dev, err := OpenLUKS(path, []byte(interopPassphrase), WithBudget(probe))
	if err != nil {
		t.Fatal(err)
	}
	dev.Close()
	cost := probe.Spent()
	if cost == 0 {
		t.Fatal("an unlock charged nothing")
	}

	shared := kdfbudget.Unlimited()
	shared.MaxWork = cost
	dev, err = OpenLUKS(path, []byte(interopPassphrase), WithBudget(shared))
	if err != nil {
		t.Fatalf("first unlock with exactly its cost: %v", err)
	}
	dev.Close()
	if _, err := OpenLUKS(path, []byte(interopPassphrase), WithBudget(shared)); !errors.Is(err, kdfbudget.ErrLimit) {
		t.Fatalf("second unlock on the drained budget: err = %v, want ErrLimit", err)
	}
}

// TestOpenLUKS_NormalVolumesOpenWithDefaultBudget: real cryptsetup volumes
// still open without any option (see interop_test.go) and under an explicit
// default budget.
func TestOpenLUKS_NormalVolumesOpenWithDefaultBudget(t *testing.T) {
	for _, fixture := range []string{"cryptsetup_luks2_default.img.gz", "cryptsetup_luks2_pbkdf2.img.gz"} {
		path := decompressFixture(t, fixture)
		dev, err := OpenLUKS(path, []byte(interopPassphrase), WithBudget(kdfbudget.Default()))
		if err != nil {
			t.Fatalf("%s: %v", fixture, err)
		}
		dev.Close()
	}
}

// hostileAPFS formats an APFS container whose Argon2id locker asks for threads
// lanes: structurally valid for the APFS backend (1 to 255), far above what the
// facade allows by default.
func hostileAPFS(t *testing.T, threads uint16) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hostile.apfs")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	dev, err := apfsfde.FormatArgon2id(path, []byte("pw"), apfsfde.Argon2idParams{TimeCost: 1, MemoryKiB: 8 * 255, Parallelism: threads})
	if err != nil {
		t.Fatalf("FormatArgon2id: %v", err)
	}
	dev.Close()
	return path
}

// TestOpenAPFS_ExcessArgon2ThreadsRefusedByDefault: the APFS backend takes up
// to 255 Argon2 threads; the facade's default budget caps them at 4.
func TestOpenAPFS_ExcessArgon2ThreadsRefusedByDefault(t *testing.T) {
	path := hostileAPFS(t, 200)
	for name, open := range map[string]func() (Device, error){
		"OpenAPFS": func() (Device, error) { return OpenAPFS(path, []byte("pw")) },
		"Open":     func() (Device, error) { return Open(APFS, path, []byte("pw")) },
		"Auto":     func() (Device, error) { return Open(Auto, path, []byte("pw")) },
	} {
		dev, err := open()
		if err == nil {
			dev.Close()
			t.Fatalf("%s: a locker of 200 Argon2 threads opened by default", name)
		}
		if !errors.Is(err, kdfbudget.ErrLimit) || !errors.Is(err, apfsfde.ErrLimit) {
			t.Errorf("%s: err = %v, want ErrLimit", name, err)
		}
	}
	// A caller that trusts the volume says so.
	dev, err := OpenAPFS(path, []byte("pw"), WithBudget(kdfbudget.Unlimited()))
	if err != nil {
		t.Fatalf("with an unlimited budget: %v", err)
	}
	dev.Close()
}

// TestOpenAPFS_CallerBudgetThreadCap: Budget.MaxThreads is the cap.
func TestOpenAPFS_CallerBudgetThreadCap(t *testing.T) {
	path := hostileAPFS(t, 8)
	b := kdfbudget.Unlimited()
	b.MaxThreads = 4
	if _, err := OpenAPFS(path, []byte("pw"), WithBudget(b)); !errors.Is(err, kdfbudget.ErrLimit) {
		t.Fatalf("8 threads under MaxThreads 4: err = %v, want ErrLimit", err)
	}
	b.MaxThreads = 8
	dev, err := OpenAPFS(path, []byte("pw"), WithBudget(b))
	if err != nil {
		t.Fatalf("8 threads under MaxThreads 8: %v", err)
	}
	dev.Close()
}

// TestOpenAPFS_NormalVolumesOpen: volumes made with ordinary parameters open by
// default, through the path and the reader entry points.
func TestOpenAPFS_NormalVolumesOpen(t *testing.T) {
	pbkdf2 := filepath.Join(t.TempDir(), "n.apfs")
	f, err := os.Create(pbkdf2)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	dev, err := Create(APFS, pbkdf2, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	dev.Close()

	argon := filepath.Join(t.TempDir(), "a.apfs")
	if f, err = os.Create(argon); err != nil {
		t.Fatal(err)
	}
	f.Close()
	adev, err := apfsfde.FormatArgon2id(argon, []byte("pw"), apfsfde.Argon2idParams{})
	if err != nil {
		t.Fatal(err)
	}
	adev.Close()

	for _, p := range []string{pbkdf2, argon} {
		dev, err := OpenAPFS(p, []byte("pw"))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		dev.Close()
		rw, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		dev, err = OpenFrom(Auto, rw, []byte("pw"))
		if err != nil {
			rw.Close()
			t.Fatalf("%s from reader: %v", p, err)
		}
		dev.Close()
	}
}
