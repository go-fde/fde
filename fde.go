// Package fde provides a uniform Device interface for Full-Disk Encryption
// block devices, abstracting over LUKS, APFS FileVault 2, BitLocker,
// VeraCrypt, and plaintext (CLEAR) backends.
//
// The LUKS and APFS backends expose a Device whose ReadAt and WriteAt
// methods transparently decrypt and encrypt I/O using their respective
// volume keys. The BitLocker and VeraCrypt backends read only: their WriteAt
// returns bitlocker.ErrReadOnly or veracrypt.ErrReadOnly. The CLEAR backend
// is a passthrough that applies no encryption.
//
// # Supported backends
//
//   - LUKS 1/2 via github.com/go-fde/luks
//   - APFS FileVault 2 via github.com/go-fde/apfs
//   - BitLocker (Windows 7+, To Go), read-only, via github.com/go-fde/bitlocker
//   - VeraCrypt and TrueCrypt, read-only, by name only, via github.com/go-fde/veracrypt
//   - Plaintext passthrough via github.com/go-fde/clear
//
// # Usage
//
//	// Open a raw LUKS device:
//	dev, err := fde.OpenLUKS("/path/to/disk.luks", []byte("passphrase"))
//
//	// Stack APFS FDE on top of a QCOW2 virtual disk:
//	qdev, _ := qcow2.OpenDevice("/path/to/disk.qcow2")
//	dev, err := fde.OpenAPFSFrom(qdev, []byte("passphrase"))
//
//	// Auto-detect format and open:
//	dev, err := fde.Open(fde.Auto, "/path/to/disk", []byte("passphrase"))
package fde

import (
	"errors"
	"fmt"
	"io"
	"os"

	apfsfde "github.com/go-fde/apfs"
	"github.com/go-fde/bitlocker"
	cleardev "github.com/go-fde/clear"
	luks "github.com/go-fde/luks"
	"github.com/go-fde/veracrypt"
)

// RW is the minimal read-write-close interface accepted by OpenLUKSFrom and
// OpenAPFSFrom. It allows FDE to be layered on top of any block device, such
// as a QCOW2 virtual disk.
type RW interface {
	io.ReaderAt
	WriteAt(p []byte, off int64) (int, error)
	io.Closer
}

// Device is the uniform interface exposed by all FDE backends. ReadAt and
// WriteAt transparently decrypt and encrypt data using the volume key.
//
// LUKS offsets are relative to the start of the plaintext payload.
// APFS offsets are absolute (relative to the start of the container device).
// BitLocker offsets are those of the decrypted volume, which has the size of
// the device.
type Device interface {
	io.ReaderAt
	WriteAt(p []byte, off int64) (int, error)
	// Size returns the byte length of the plaintext payload.
	// Returns 0 when the size is not exposed by the backend (APFS).
	Size() int64
	// Close releases all resources held by the device.
	Close() error
}

// Type identifies the FDE backend used by Create and CreateFrom.
type Type int

const (
	// LUKS selects the LUKS 1/2 backend.
	LUKS Type = iota
	// APFS selects the APFS FileVault 2 backend.
	APFS
	// CLEAR selects the plaintext passthrough backend (no encryption).
	CLEAR
	// Auto causes Open and OpenFrom to detect the format automatically.
	Auto
	// BITLOCKER selects the BitLocker backend (read-only). It comes after
	// Auto so that the values of the earlier constants do not change.
	BITLOCKER
	// VERACRYPT selects the VeraCrypt and TrueCrypt backend (read-only).
	// Auto never chooses it: a VeraCrypt header is indistinguishable from
	// random bytes, so the caller names it.
	VERACRYPT
)

// luksHeaderMagic is the 6-byte magic at the start of any LUKS container.
const luksHeaderMagic = "LUKS\xba\xbe"

// apfsMagic is the 4-byte NX superblock magic at offset 32 of an APFS
// container. Apple writes the ASCII bytes 'N','X','S','B' (little-endian
// uint32 = 0x4253584E). An earlier version of this constant was "BSXN"
// — self-consistent for round-tripping our own writer output but
// incompatible with any real Apple-produced container, where Detect
// would silently report CLEAR.
const apfsMagic = "NXSB"

// Detect reads the header of the file at path and returns the detected Type.
// Returns CLEAR when no known FDE header is found.
func Detect(path string) (Type, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("fde: detect %s: %w", path, err)
	}
	defer f.Close()
	return detectReader(f), nil
}

// DetectFrom reads from rw and returns the detected Type.
// Returns CLEAR when no known FDE header is found.
func DetectFrom(rw io.ReaderAt) (Type, error) {
	return detectReader(rw), nil
}

// detectReader probes r for a known FDE header and returns the detected Type.
// BitLocker needs the whole first sector: a To Go volume carries the FAT
// signature "MSWIN4.1" and is told from plain FAT32 by an identifier at
// offset 424, which bitlocker.Detect checks.
func detectReader(r io.ReaderAt) Type {
	buf := make([]byte, 36)
	n, _ := r.ReadAt(buf, 0)
	if n >= 6 && string(buf[:6]) == luksHeaderMagic {
		return LUKS
	}
	if n >= 36 && string(buf[32:36]) == apfsMagic {
		return APFS
	}
	if bitlocker.Detect(r) {
		return BITLOCKER
	}
	return CLEAR
}

// Open opens an FDE device of the given type at path, unlocking it with
// passphrase. It dispatches based on kind; when kind is Auto the format is
// detected from the file header.
// For CLEAR devices passphrase is ignored.
func Open(kind Type, path string, passphrase []byte) (Device, error) {
	if kind == Auto {
		detected, err := Detect(path)
		if err != nil {
			return nil, err
		}
		kind = detected
	}
	switch kind {
	case LUKS:
		return OpenLUKS(path, passphrase)
	case APFS:
		return OpenAPFS(path, passphrase)
	case BITLOCKER:
		return OpenBitLocker(path, passphrase)
	case VERACRYPT:
		return OpenVeraCrypt(path, passphrase)
	case CLEAR:
		return OpenClear(path)
	default:
		return nil, fmt.Errorf("fde: unknown type %d", kind)
	}
}

// OpenFrom opens an FDE device of the given type on top of rw, unlocking it
// with passphrase. When kind is Auto the format is detected from rw's header.
// For CLEAR devices passphrase is ignored.
func OpenFrom(kind Type, rw RW, passphrase []byte) (Device, error) {
	if kind == Auto {
		// DetectFrom never errors — it reads from rw and classifies by magic.
		kind, _ = DetectFrom(rw)
	}
	switch kind {
	case LUKS:
		return OpenLUKSFrom(rw, passphrase)
	case APFS:
		return OpenAPFSFrom(rw, passphrase)
	case BITLOCKER:
		return OpenBitLockerFrom(rw, passphrase)
	case VERACRYPT:
		return OpenVeraCryptFrom(rw, passphrase)
	case CLEAR:
		return OpenClearFrom(rw)
	default:
		return nil, fmt.Errorf("fde: unknown type %d", kind)
	}
}

// Create initialises a new FDE container of the given type at path, encrypting
// it with passphrase. The file must already exist. Returns an opened Device
// ready for payload I/O.
// For CLEAR, no initialisation is performed; the file is opened as a
// passthrough device.
func Create(kind Type, path string, passphrase []byte) (Device, error) {
	switch kind {
	case LUKS:
		dev, err := luks.Format(path, passphrase)
		if err != nil {
			return nil, fmt.Errorf("fde: create LUKS %s: %w", path, err)
		}
		return &luksDevice{dev: dev}, nil
	case APFS:
		dev, err := apfsfde.Format(path, passphrase)
		if err != nil {
			return nil, fmt.Errorf("fde: create APFS %s: %w", path, err)
		}
		return &apfsDevice{dev: dev}, nil
	case BITLOCKER:
		return nil, ErrCreateBitLocker
	case VERACRYPT:
		return nil, ErrCreateVeraCrypt
	case CLEAR:
		return OpenClear(path)
	default:
		return nil, fmt.Errorf("fde: unknown type %d", kind)
	}
}

// CreateFrom initialises a new FDE container of the given type on rw,
// encrypting it with passphrase. Returns an opened Device ready for payload I/O.
// For CLEAR, no initialisation is performed; rw is wrapped as a passthrough device.
func CreateFrom(kind Type, rw RW, passphrase []byte) (Device, error) {
	switch kind {
	case LUKS:
		dev, err := luks.FormatOn(rw, passphrase)
		if err != nil {
			return nil, fmt.Errorf("fde: create LUKS from device: %w", err)
		}
		return &luksDevice{dev: dev}, nil
	case APFS:
		dev, err := apfsfde.FormatOn(rw, passphrase)
		if err != nil {
			return nil, fmt.Errorf("fde: create APFS from device: %w", err)
		}
		return &apfsDevice{dev: dev}, nil
	case BITLOCKER:
		return nil, ErrCreateBitLocker
	case VERACRYPT:
		return nil, ErrCreateVeraCrypt
	case CLEAR:
		return OpenClearFrom(rw)
	default:
		return nil, fmt.Errorf("fde: unknown type %d", kind)
	}
}

// OpenLUKS opens the LUKS1/LUKS2 encrypted container at path, unlocking it
// with passphrase. path may be a raw disk image or block device file.
func OpenLUKS(path string, passphrase []byte) (Device, error) {
	dev, err := luks.Open(path, passphrase)
	if err != nil {
		return nil, fmt.Errorf("fde: open LUKS %s: %w", path, err)
	}
	return &luksDevice{dev: dev}, nil
}

// OpenLUKSFrom opens a LUKS container on top of an existing block device rw,
// unlocking it with passphrase. This allows LUKS to be stacked on a QCOW2
// device or any other RW backend. Close on the returned Device also closes rw.
func OpenLUKSFrom(rw RW, passphrase []byte) (Device, error) {
	dev, err := luks.OpenFrom(rw, passphrase)
	if err != nil {
		return nil, fmt.Errorf("fde: open LUKS from device: %w", err)
	}
	return &luksDevice{dev: dev}, nil
}

// OpenAPFS opens the FileVault 2-encrypted APFS container at path, unlocking
// it with passphrase. path may be a raw disk image or block device file.
func OpenAPFS(path string, passphrase []byte) (Device, error) {
	dev, err := apfsfde.Open(path, passphrase)
	if err != nil {
		return nil, fmt.Errorf("fde: open APFS FDE %s: %w", path, err)
	}
	return &apfsDevice{dev: dev}, nil
}

// OpenAPFSFrom opens a FileVault 2 APFS container on top of an existing block
// device rw, unlocking it with passphrase. Close on the returned Device also
// closes rw.
func OpenAPFSFrom(rw RW, passphrase []byte) (Device, error) {
	dev, err := apfsfde.OpenFrom(rw, passphrase)
	if err != nil {
		return nil, fmt.Errorf("fde: open APFS FDE from device: %w", err)
	}
	return &apfsDevice{dev: dev}, nil
}

// ErrCreateBitLocker is returned by Create and CreateFrom for BITLOCKER: the
// backend reads volumes Windows made and does not write new ones.
var ErrCreateBitLocker = errors.New("fde: BitLocker volumes cannot be created, the backend is read-only")

// OpenBitLocker opens the BitLocker volume at path read-only, unlocking it
// with passphrase: a password, a recovery password ("123456-…"), the
// contents of a .BEK startup key file, or nil for a clear-key volume.
func OpenBitLocker(path string, passphrase []byte) (Device, error) {
	dev, err := bitlocker.Open(path, passphrase)
	if err != nil {
		return nil, fmt.Errorf("fde: open BitLocker %s: %w", path, err)
	}
	return dev, nil
}

// sizer is a device that knows its length; os.File is told by Stat.
type sizer interface{ Size() int64 }

// deviceSize is rw's length, from a Size() int64 method (as Device and most
// virtual disks have) or a Stat() like *os.File's. BitLocker and VeraCrypt
// need it: their headers sit at both ends of the device.
func deviceSize(rw RW) (int64, error) {
	switch s := rw.(type) {
	case sizer:
		return s.Size(), nil
	case interface{ Stat() (os.FileInfo, error) }:
		st, err := s.Stat()
		if err != nil {
			return 0, err
		}
		return st.Size(), nil
	}
	return 0, fmt.Errorf("%T has neither Size nor Stat", rw)
}

// OpenBitLockerFrom opens a BitLocker volume on top of rw. BitLocker maps the
// whole device, so rw must tell its size (see deviceSize). Close on the
// returned Device also closes rw.
func OpenBitLockerFrom(rw RW, passphrase []byte) (Device, error) {
	size, err := deviceSize(rw)
	if err != nil {
		return nil, fmt.Errorf("fde: open BitLocker from device: %w", err)
	}
	dev, err := bitlocker.OpenFrom(rw, size, passphrase, bitlocker.DefaultLimits)
	if err != nil {
		return nil, fmt.Errorf("fde: open BitLocker from device: %w", err)
	}
	return dev, nil
}

// ErrCreateVeraCrypt is returned by Create and CreateFrom for VERACRYPT: the
// backend reads volumes and does not write new ones.
var ErrCreateVeraCrypt = errors.New("fde: VeraCrypt volumes cannot be created, the backend is read-only")

// OpenVeraCrypt opens the VeraCrypt or TrueCrypt volume at path read-only
// with passphrase as its password, trying every KDF and cipher the backend
// supports (about half a second each). For keyfiles, a PIM, a hidden
// volume, or to name the KDF and cipher, use github.com/go-fde/veracrypt
// directly. A VeraCrypt header is indistinguishable from random bytes, so
// Auto never chooses this type: the caller names it.
func OpenVeraCrypt(path string, passphrase []byte) (Device, error) {
	dev, err := veracrypt.Open(path, veracrypt.Options{Password: passphrase})
	if err != nil {
		return nil, fmt.Errorf("fde: open VeraCrypt %s: %w", path, err)
	}
	return dev, nil
}

// OpenVeraCryptFrom opens a VeraCrypt or TrueCrypt volume on top of rw,
// which must tell its size (see deviceSize). Close on the returned Device
// also closes rw.
func OpenVeraCryptFrom(rw RW, passphrase []byte) (Device, error) {
	size, err := deviceSize(rw)
	if err != nil {
		return nil, fmt.Errorf("fde: open VeraCrypt from device: %w", err)
	}
	dev, err := veracrypt.OpenFrom(rw, size, veracrypt.Options{Password: passphrase})
	if err != nil {
		return nil, fmt.Errorf("fde: open VeraCrypt from device: %w", err)
	}
	return dev, nil
}

// luksDevice wraps a *luks.Device as a Device.
type luksDevice struct{ dev *luks.Device }

func (d *luksDevice) ReadAt(p []byte, off int64) (int, error)  { return d.dev.ReadAt(p, off) }
func (d *luksDevice) WriteAt(p []byte, off int64) (int, error) { return d.dev.WriteAt(p, off) }
func (d *luksDevice) Size() int64                              { return d.dev.Size() }
func (d *luksDevice) Close() error                             { return d.dev.Close() }

// apfsDevice wraps a *apfsfde.Device as a Device.
// APFS FileVault containers do not expose the plaintext payload size; Size
// always returns 0.
type apfsDevice struct{ dev *apfsfde.Device }

func (d *apfsDevice) ReadAt(p []byte, off int64) (int, error)  { return d.dev.ReadAt(p, off) }
func (d *apfsDevice) WriteAt(p []byte, off int64) (int, error) { return d.dev.WriteAt(p, off) }
func (d *apfsDevice) Size() int64                              { return 0 }
func (d *apfsDevice) Close() error                             { return d.dev.Close() }

// OpenClear opens the plaintext block device at path as a passthrough Device.
// No decryption is applied; I/O is forwarded directly to the file.
func OpenClear(path string) (Device, error) {
	dev, err := cleardev.Open(path)
	if err != nil {
		return nil, fmt.Errorf("fde: open clear %s: %w", path, err)
	}
	return &clearDevice{dev: dev}, nil
}

// OpenClearFrom wraps rw as a passthrough Device with no encryption.
func OpenClearFrom(rw RW) (Device, error) {
	// cleardev.OpenFrom is infallible — it just wraps rw in a passthrough.
	dev, _ := cleardev.OpenFrom(rw)
	return &clearDevice{dev: dev}, nil
}

// clearDevice wraps a *cleardev.Device as a Device.
type clearDevice struct{ dev *cleardev.Device }

func (d *clearDevice) ReadAt(p []byte, off int64) (int, error)  { return d.dev.ReadAt(p, off) }
func (d *clearDevice) WriteAt(p []byte, off int64) (int, error) { return d.dev.WriteAt(p, off) }
func (d *clearDevice) Size() int64                              { return d.dev.Size() }
func (d *clearDevice) Close() error                             { return d.dev.Close() }
