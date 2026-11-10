package fde

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/go-fde/veracrypt"
)

// testdata/veracrypt_aes_sha512_fde.img.gz is written by go-fde/veracrypt
// (VERACRYPT_WRITE_FIXTURE=… go test -run TestWriteFixture): magic VERA,
// PBKDF2-SHA-512 at 500,000 iterations, AES-XTS, password "fde", a 1 KiB
// volume whose bytes are byte(i*31 + i/512). Interoperability with volumes
// VeraCrypt and TrueCrypt made is tested in go-fde/veracrypt against
// cryptsetup's corpus.
const (
	veracryptFixture  = "veracrypt_aes_sha512_fde.img.gz"
	veracryptPassword = "fde"
	veracryptSize     = 1024
)

func checkVeraCryptDevice(t *testing.T, dev Device) {
	t.Helper()
	if dev.Size() != veracryptSize {
		t.Fatalf("size %d, want %d", dev.Size(), veracryptSize)
	}
	buf := make([]byte, veracryptSize)
	if _, err := dev.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	for i, b := range buf {
		if want := byte(i*31 + i/512); b != want {
			t.Fatalf("byte %d is %#x, want %#x", i, b, want)
		}
	}
	if _, err := dev.WriteAt(buf, 0); !errors.Is(err, veracrypt.ErrReadOnly) {
		t.Errorf("WriteAt: %v, want veracrypt.ErrReadOnly", err)
	}
}

func veracryptBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(decompressFixture(t, veracryptFixture))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpen_VeraCrypt(t *testing.T) {
	path := decompressFixture(t, veracryptFixture)
	dev, err := Open(VERACRYPT, path, []byte(veracryptPassword))
	if err != nil {
		t.Fatal(err)
	}
	checkVeraCryptDevice(t, dev)
	if err := dev.Close(); err != nil {
		t.Error(err)
	}
	if _, err := OpenVeraCrypt(path, []byte("nope")); !errors.Is(err, veracrypt.ErrWrongSecret) {
		t.Errorf("wrong passphrase: %v, want veracrypt.ErrWrongSecret", err)
	}
}

// Auto cannot see VeraCrypt: its header looks like random bytes.
func TestDetect_VeraCryptIsNotDetected(t *testing.T) {
	got, err := Detect(decompressFixture(t, veracryptFixture))
	if err != nil {
		t.Fatal(err)
	}
	if got != CLEAR {
		t.Fatalf("Detect: got %d, want CLEAR", got)
	}
}

func TestOpenVeraCryptFrom(t *testing.T) {
	img := veracryptBytes(t)
	dev, err := OpenFrom(VERACRYPT, sizedRW{bytes.NewReader(img)}, []byte(veracryptPassword))
	if err != nil {
		t.Fatal(err)
	}
	checkVeraCryptDevice(t, dev)
	if err := dev.Close(); err != nil {
		t.Error(err)
	}

	// Every wrong passphrase costs a trial over every KDF (seconds, minutes
	// under -race and QEMU): TestOpen_VeraCrypt pays it once. A device too
	// small for a header is refused before any derivation.
	if _, err := OpenVeraCryptFrom(sizedRW{bytes.NewReader(img[:100])}, []byte("nope")); err == nil {
		t.Error("a 100-byte device opened")
	}
	if _, err := OpenVeraCryptFrom(unsizedRW{sizedRW{bytes.NewReader(img)}}, nil); err == nil {
		t.Error("a device without a size opened")
	}
}

func TestCreate_VeraCrypt(t *testing.T) {
	if _, err := Create(VERACRYPT, "unused", nil); !errors.Is(err, ErrCreateVeraCrypt) {
		t.Errorf("Create: %v", err)
	}
	if _, err := CreateFrom(VERACRYPT, sizedRW{bytes.NewReader(nil)}, nil); !errors.Is(err, ErrCreateVeraCrypt) {
		t.Errorf("CreateFrom: %v", err)
	}
}
