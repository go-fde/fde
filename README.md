<p align="center"><img src="https://raw.githubusercontent.com/go-fde/brand/main/social/go-fde.png" alt="go-fde/fde" width="720"></p>

# fde

[![ci](https://github.com/go-fde/fde/actions/workflows/ci.yml/badge.svg)](https://github.com/go-fde/fde/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-fde/fde.svg)](https://pkg.go.dev/github.com/go-fde/fde)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Unified dispatcher for Full-Disk Encryption block devices.

## Overview

The `fde` package provides a single `Device` interface and a set of dispatcher
functions that abstract over five backends:

| Backend | Type constant | Package |
|---------|---------------|---------|
| LUKS 1/2 | `fde.LUKS` | `github.com/go-fde/luks` |
| APFS FileVault 2 | `fde.APFS` | `github.com/go-fde/apfs` |
| BitLocker (Windows 7+, To Go), **read-only** | `fde.BITLOCKER` | `github.com/go-fde/bitlocker` |
| VeraCrypt and TrueCrypt, **read-only**, never auto-detected | `fde.VERACRYPT` | `github.com/go-fde/veracrypt` |
| Plaintext passthrough | `fde.CLEAR` | `github.com/go-fde/clear` |

Pass `fde.Auto` to any `Open` or `OpenFrom` call to auto-detect the format
from the on-disk header. VeraCrypt is the exception: its header cannot be told
apart from random bytes, so it must be named.

## Format detection

`Detect(path)` and `DetectFrom(rw)` identify the format from the first sector
of the device:

- Bytes 0–5 equal `"LUKS\xba\xbe"` → `LUKS`
- Bytes 32–35 equal `"NXSB"` → `APFS`
- Bytes 3–10 equal `"-FVE-FS-"`, or `"MSWIN4.1"` with BitLocker's identifier
  at byte 424 (To Go; plain FAT32 also writes `"MSWIN4.1"`) → `BITLOCKER`
- Otherwise → `CLEAR` (a VeraCrypt volume, among others, detects as `CLEAR`)

## BitLocker

The secret passed as `passphrase` can be:

- a password;
- a recovery password (`"123456-…"`, 48 digits);
- the contents of a `.BEK` startup key file;
- `nil` for a volume whose protection is suspended (a clear key).

`WriteAt` returns `bitlocker.ErrReadOnly`. `Create(fde.BITLOCKER, …)` returns
`fde.ErrCreateBitLocker`. `OpenFrom` needs the device's size: an `RW` with a
`Size() int64` method, or with `Stat()` like `*os.File`. The decrypted volume
matches what cryptsetup's `bitlkOpen` maps; the
[backend's README](https://github.com/go-fde/bitlocker) says how that is
checked and what it refuses.

## VeraCrypt

`Open(fde.VERACRYPT, path, password)` opens a VeraCrypt or TrueCrypt volume
read-only. Nothing on disk names the key derivation or the cipher, so the
backend tries each pair until the header decrypts, as VeraCrypt itself does.
With a wrong password every pair is tried, which takes several seconds; the
error is `veracrypt.ErrWrongSecret`.

The shorthand passes only a password. Keyfiles, a PIM, hidden volumes, backup
headers, or naming the KDF and cipher need
[`github.com/go-fde/veracrypt`](https://github.com/go-fde/veracrypt) directly;
its README lists the supported ciphers and KDFs.

`WriteAt` returns `veracrypt.ErrReadOnly`. `Create(fde.VERACRYPT, …)` returns
`fde.ErrCreateVeraCrypt`. `OpenFrom` needs the device's size, as for BitLocker.

## Usage

### Open an existing device (explicit type)

```go
import "github.com/go-fde/fde"

// LUKS
dev, err := fde.Open(fde.LUKS, "/dev/sdb", []byte("passphrase"))

// APFS
dev, err := fde.Open(fde.APFS, "/dev/disk2s2", []byte("passphrase"))

// VeraCrypt (never auto-detected)
dev, err := fde.Open(fde.VERACRYPT, "/path/to/volume.hc", []byte("password"))

// Plaintext
dev, err := fde.Open(fde.CLEAR, "/path/to/disk.raw", nil)
```

### Open with auto-detection

```go
dev, err := fde.Open(fde.Auto, "/path/to/disk", []byte("passphrase"))
if err != nil {
    log.Fatal(err)
}
defer dev.Close()

buf := make([]byte, 4096)
_, err = dev.ReadAt(buf, 0)
```

### Detect format without opening

```go
kind, err := fde.Detect("/path/to/disk")
switch kind {
case fde.LUKS:
    fmt.Println("LUKS container")
case fde.APFS:
    fmt.Println("APFS FileVault 2 container")
case fde.BITLOCKER:
    fmt.Println("BitLocker volume")
case fde.CLEAR:
    fmt.Println("plaintext device")
}
```

### Layer on top of another block device (e.g. QCOW2)

`OpenFrom` and `CreateFrom` accept any value satisfying `fde.RW`:

```go
interface {
    io.ReaderAt
    WriteAt([]byte, int64) (int, error)
    io.Closer
}
```

```go
import (
    "github.com/go-fde/fde"
    qcow2 "github.com/go-diskimages/qcow2"
)

qdev, err := qcow2.OpenDevice("disk.qcow2")
if err != nil { log.Fatal(err) }

// Auto-detect: the QCOW2 virtual disk may hold LUKS, APFS, or raw data.
dev, err := fde.OpenFrom(fde.Auto, qdev, []byte("passphrase"))
if err != nil {
    qdev.Close()
    log.Fatal(err)
}
defer dev.Close()
```

### Create (initialise) a new container

`Create` and `CreateFrom` write a fresh container header to an existing file
and return an opened Device ready for payload I/O. The passphrase is ignored
for `CLEAR` (no header is written).

```go
// Create a new LUKS1 container on a pre-allocated file.
f, _ := os.Create("disk.luks")
f.Close()

dev, err := fde.Create(fde.LUKS, "disk.luks", []byte("passphrase"))
if err != nil { log.Fatal(err) }
defer dev.Close()

// Write payload starting at offset 0 (LUKS) or block 2 (APFS).
dev.WriteAt(myData, 0)
```

## API reference

### Opening and format detection

| Function | Description |
|----------|-------------|
| `Detect(path) (Type, error)` | Detect format from file header |
| `DetectFrom(rw) (Type, error)` | Detect format from an `io.ReaderAt` |
| `Open(kind, path, passphrase) (Device, error)` | Open device by path; `Auto` auto-detects |
| `OpenFrom(kind, rw, passphrase) (Device, error)` | Open device from an `RW`; `Auto` auto-detects |
| `OpenLUKS(path, passphrase) (Device, error)` | LUKS shorthand |
| `OpenLUKSFrom(rw, passphrase) (Device, error)` | LUKS-on-RW shorthand |
| `OpenAPFS(path, passphrase) (Device, error)` | APFS shorthand |
| `OpenAPFSFrom(rw, passphrase) (Device, error)` | APFS-on-RW shorthand |
| `OpenBitLocker(path, passphrase) (Device, error)` | BitLocker shorthand (read-only) |
| `OpenBitLockerFrom(rw, passphrase) (Device, error)` | BitLocker-on-RW shorthand; `rw` must tell its size |
| `OpenVeraCrypt(path, password) (Device, error)` | VeraCrypt/TrueCrypt shorthand (read-only) |
| `OpenVeraCryptFrom(rw, password) (Device, error)` | VeraCrypt-on-RW shorthand; `rw` must tell its size |
| `OpenClear(path) (Device, error)` | Plaintext shorthand |
| `OpenClearFrom(rw) (Device, error)` | Plaintext-on-RW shorthand |

### Container creation

| Function | Description |
|----------|-------------|
| `Create(kind, path, passphrase) (Device, error)` | Write container header to existing file (not BitLocker or VeraCrypt) |
| `CreateFrom(kind, rw, passphrase) (Device, error)` | Write container header to existing `RW` (not BitLocker or VeraCrypt) |

### `Device` interface

| Method | LUKS offset semantics | APFS offset semantics | CLEAR offset semantics |
|--------|-----------------------|-----------------------|------------------------|
| `ReadAt(p, off)` | Relative to payload start | Absolute from container start | Absolute from file start |
| `WriteAt(p, off)` | Relative to payload start | Absolute from container start | Absolute from file start |
| `Size() int64` | Plaintext payload size (0 if unknown) | Always 0 | File size at open time |
| `Close()` | Closes underlying device | Closes underlying device | Closes underlying device |

## Offset semantics

LUKS and CLEAR offsets differ from APFS offsets:

- **LUKS** `ReadAt`/`WriteAt` offsets are **relative to payload sector 0** — the
  LUKS header overhead is hidden.
- **APFS** `ReadAt`/`WriteAt` offsets are **absolute from the container start**
  (byte 0 of the device). Block 0 is the NX superblock, block 1 is the key bag,
  payload starts at block 2.
- **CLEAR** `ReadAt`/`WriteAt` offsets are **absolute from the file start**.
- **BITLOCKER** `ReadAt` offsets are those of the **decrypted volume**, which
  has the device's size: offset 0 is the volume's own boot sector (NTFS,
  exFAT or FAT). `Size()` is the device size in whole sectors.
- **VERACRYPT** `ReadAt` offsets are **relative to the data area**, as for
  LUKS: offset 0 is the volume's file system. `Size()` is the volume size the
  header records.
