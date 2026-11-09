package fde

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/go-fde/bitlocker"
)

// testdata/bitlocker_xts128_password_fde.img.gz is written by go-fde/bitlocker
// (BITLK_WRITE_FIXTURE=… go test -run TestWriteFixture): password "fde",
// AES-XTS-128, 264 KiB. Its decrypted bytes follow the writer's pattern,
// byte(i*31 + i/512) outside the zeroed metadata areas. Interoperability with
// volumes Windows made is tested in go-fde/bitlocker against cryptsetup's.
const (
	bitlockerFixture  = "bitlocker_xts128_password_fde.img.gz"
	bitlockerPassword = "fde"
	bitlockerSize     = 264 << 10
)

func checkBitLockerDevice(t *testing.T, dev Device) {
	t.Helper()
	if dev.Size() != bitlockerSize {
		t.Fatalf("size %d, want %d", dev.Size(), bitlockerSize)
	}
	buf := make([]byte, 1024)
	if _, err := dev.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	for i, b := range buf {
		if want := byte(i*31 + i/512); b != want {
			t.Fatalf("byte %d is %#x, want %#x", i, b, want)
		}
	}
	if _, err := dev.WriteAt(buf, 0); !errors.Is(err, bitlocker.ErrReadOnly) {
		t.Errorf("WriteAt: %v, want bitlocker.ErrReadOnly", err)
	}
}

func TestDetect_BitLocker(t *testing.T) {
	path := decompressFixture(t, bitlockerFixture)
	got, err := Detect(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != BITLOCKER {
		t.Fatalf("Detect: want BITLOCKER, got %d", got)
	}
}

func TestOpen_Auto_BitLocker(t *testing.T) {
	path := decompressFixture(t, bitlockerFixture)
	dev, err := Open(Auto, path, []byte(bitlockerPassword))
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	checkBitLockerDevice(t, dev)
}

func TestOpenBitLocker_WrongPassphrase(t *testing.T) {
	path := decompressFixture(t, bitlockerFixture)
	if _, err := OpenBitLocker(path, []byte("nope")); !errors.Is(err, bitlocker.ErrWrongSecret) {
		t.Fatalf("%v, want bitlocker.ErrWrongSecret", err)
	}
}

func TestOpenFrom_Auto_BitLocker_File(t *testing.T) {
	f, err := os.Open(decompressFixture(t, bitlockerFixture))
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenFrom(Auto, readOnlyFile{f}, []byte(bitlockerPassword))
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	checkBitLockerDevice(t, dev)
}

// readOnlyFile adapts an *os.File opened read-only to RW, keeping its Stat.
type readOnlyFile struct{ *os.File }

// sizedRW is an in-memory device with a Size method, like a virtual disk.
type sizedRW struct{ r *bytes.Reader }

func (s sizedRW) ReadAt(p []byte, off int64) (int, error) { return s.r.ReadAt(p, off) }
func (s sizedRW) WriteAt([]byte, int64) (int, error)      { return 0, errors.New("read-only") }
func (s sizedRW) Close() error                            { return nil }
func (s sizedRW) Size() int64                             { return s.r.Size() }

// unsizedRW has neither Size nor Stat.
type unsizedRW struct{ sizedRW }

func (unsizedRW) Size() {} // shadows sizedRW.Size with another signature

func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(decompressFixture(t, bitlockerFixture))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenBitLockerFrom(t *testing.T) {
	img := fixtureBytes(t)
	dev, err := OpenFrom(BITLOCKER, sizedRW{bytes.NewReader(img)}, []byte(bitlockerPassword))
	if err != nil {
		t.Fatal(err)
	}
	checkBitLockerDevice(t, dev)
	if err := dev.Close(); err != nil {
		t.Error(err)
	}

	if _, err := OpenBitLockerFrom(sizedRW{bytes.NewReader(img)}, []byte("nope")); !errors.Is(err, bitlocker.ErrWrongSecret) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, err := OpenBitLockerFrom(unsizedRW{sizedRW{bytes.NewReader(img)}}, nil); err == nil {
		t.Error("a device without a size opened")
	}
	f, err := os.Open(decompressFixture(t, bitlockerFixture))
	if err != nil {
		t.Fatal(err)
	}
	f.Close() // Stat now fails
	if _, err := OpenBitLockerFrom(readOnlyFile{f}, nil); err == nil {
		t.Error("a closed file opened")
	}
}

func TestCreate_BitLocker(t *testing.T) {
	if _, err := Create(BITLOCKER, "unused", nil); !errors.Is(err, ErrCreateBitLocker) {
		t.Errorf("Create: %v", err)
	}
	if _, err := CreateFrom(BITLOCKER, sizedRW{bytes.NewReader(nil)}, nil); !errors.Is(err, ErrCreateBitLocker) {
		t.Errorf("CreateFrom: %v", err)
	}
}

// A FAT32 volume also starts with "MSWIN4.1"; without BitLocker's identifier
// at 424 it stays CLEAR.
func TestDetect_FAT32NotBitLocker(t *testing.T) {
	img := fixtureBytes(t)[:512]
	copy(img[3:], "MSWIN4.1")
	clear(img[424:440])
	if got, _ := DetectFrom(bytes.NewReader(img)); got != CLEAR {
		t.Fatalf("got %d, want CLEAR", got)
	}
}
