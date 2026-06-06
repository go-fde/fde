package fde

// Tests for the fde package.
//
// All image builders are self-contained: they do not import internals of the
// go-fde/luks or go-fde/apfs packages, but produce images that those packages
// can parse.

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"
)

// ── LUKS1 image builder ────────────────────────────────────────────────────

const (
	luks1Magic         = "LUKS\xba\xbe"
	luks1KeySlotActive = 0x00AC71F3
	luks1Stripes       = 4000
	luks1SectorSize    = 512
	luks1KeyBytes      = 32
	luks1SlotIter      = 1000
	luks1MKIter        = 1000
	luks1KMOffset      = uint32(8)
)

func fdeRand(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func fdeXorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// fdeAfDiffuse applies the LUKS diffusion function (HMAC-SHA256) to block
// in-place. Matches hashDiffuse("sha256") in the luks package.
func fdeAfDiffuse(block []byte) {
	const digestLen = 32
	counter := make([]byte, 4)
	pos := 0
	for i := 0; pos < len(block); i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))
		chunk := len(block) - pos
		if chunk > digestLen {
			chunk = digestLen
		}
		h := hmac.New(sha256.New, counter)
		h.Write(block[pos : pos+chunk])
		sum := h.Sum(nil)
		copy(block[pos:pos+chunk], sum[:chunk])
		pos += chunk
	}
}

// fdeAfSplitKey produces an AF-split payload of key using SHA-256 diffusion.
// It is the inverse of afMerge used inside the luks package.
func fdeAfSplitKey(key []byte, stripes int) []byte {
	klen := len(key)
	out := make([]byte, klen*stripes)
	d := make([]byte, klen)
	for i := 0; i < stripes-1; i++ {
		stripe := fdeRand(klen)
		copy(out[i*klen:], stripe)
		fdeXorBytes(d, stripe)
		fdeAfDiffuse(d)
	}
	last := out[(stripes-1)*klen : stripes*klen]
	copy(last, d)
	fdeXorBytes(last, key)
	return out
}

// fdeEncryptAFBlocks encrypts an AF-split payload using AES-XTS-plain64.
// Sector size is 512; the IV equals the sector number.
func fdeEncryptAFBlocks(afData, key []byte) []byte {
	const ss = 512
	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		panic("fdeEncryptAFBlocks: " + err.Error())
	}
	out := make([]byte, len(afData))
	copy(out, afData)
	for i := 0; i*ss < len(out); i++ {
		end := (i + 1) * ss
		if end > len(out) {
			end = len(out)
		}
		c.Encrypt(out[i*ss:end], out[i*ss:end], uint64(i))
	}
	return out
}

func fdePadStr(buf []byte, s string) {
	copy(buf, s)
	for i := len(s); i < len(buf); i++ {
		buf[i] = 0
	}
}

// fdeBuildLUKS1ImageFile creates a minimal valid LUKS1 image at path,
// protecting volumeKey with passphrase.
func fdeBuildLUKS1ImageFile(t *testing.T, path string, passphrase, volumeKey []byte) {
	t.Helper()
	slotSalt := fdeRand(luks1KeyBytes)
	slotKey := pbkdf2.Key(passphrase, slotSalt, luks1SlotIter, luks1KeyBytes, sha256.New)
	afData := fdeAfSplitKey(volumeKey, luks1Stripes)
	encAF := fdeEncryptAFBlocks(afData, slotKey)
	mkSalt := fdeRand(luks1KeyBytes)
	mkDigest := pbkdf2.Key(volumeKey, mkSalt, luks1MKIter, 20, sha256.New)
	payloadOffset := uint32(8 + uint32(luks1Stripes*luks1KeyBytes)/luks1SectorSize + 8)
	fdeBuildLUKS1Write(t, path, slotSalt, mkDigest, mkSalt, encAF, payloadOffset)
}

// fdeBuildLUKS1Write serialises and writes the LUKS1 header + key material.
func fdeBuildLUKS1Write(t *testing.T, path string, slotSalt, mkDigest, mkSalt, encAF []byte, payloadOffset uint32) {
	t.Helper()
	imgSize := int(payloadOffset)*luks1SectorSize + luks1SectorSize
	img := make([]byte, imgSize)
	copy(img[0:6], luks1Magic)
	binary.BigEndian.PutUint16(img[6:8], 1)
	fdePadStr(img[8:40], "aes")
	fdePadStr(img[40:72], "xts-plain64")
	fdePadStr(img[72:104], "sha256")
	binary.BigEndian.PutUint32(img[104:108], payloadOffset)
	binary.BigEndian.PutUint32(img[108:112], luks1KeyBytes)
	copy(img[112:132], mkDigest)
	copy(img[132:164], mkSalt)
	binary.BigEndian.PutUint32(img[164:168], luks1MKIter)
	copy(img[168:208], "test-uuid-0000000000000000000000")
	base := 208
	binary.BigEndian.PutUint32(img[base:], luks1KeySlotActive)
	binary.BigEndian.PutUint32(img[base+4:], luks1SlotIter)
	copy(img[base+8:base+40], slotSalt)
	binary.BigEndian.PutUint32(img[base+40:], luks1KMOffset)
	binary.BigEndian.PutUint32(img[base+44:], uint32(luks1Stripes))
	for i := 1; i < 8; i++ {
		binary.BigEndian.PutUint32(img[208+i*48:], 0xDEAD0000)
	}
	copy(img[int(luks1KMOffset)*luks1SectorSize:], encAF)
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatalf("fdeBuildLUKS1Write: write: %v", err)
	}
}

// ── APFS FDE image builder ─────────────────────────────────────────────────

const (
	apfsTestBlkSize  = 4096
	apfsTestSectorSz = 512
	apfsTestNXMagic  = "NXSB"
	apfsTestKBVer    = uint16(2)
	apfsTestTagPass  = 0x0003
	apfsTestTagVEK   = 0x0002
	apfsTestKDFType  = uint16(0x0002)
	apfsTestKDFIter  = 1000

	// nx_keylocker (apfs_prange) at NX SB offset 1296: paddr u64 at +1296,
	// block_count u64 at +1304. Earlier versions of these tests wrote at
	// offsets 64-79 (which is nx_incompatible_features); that was wrong
	// and only worked with the matching reader bug we've also fixed.
	apfsTestNXKeylockerOff = 1296
	// Media keybag obj_phys.type — APFS_OBJECT_TYPE_MEDIA_KEYBAG, stored
	// at obj_phys offset +24 within the keybag block.
	apfsTestKBObjType = uint32(0x6b657973)
	// Entry data starts at byte 48 of the keybag block: 32-byte obj_phys
	// + 16-byte apfs_kb_locker header. Entries are 16-byte aligned.
	apfsTestKBEntryArea  = 48
	apfsTestKBEntryAlign = 16
)

// fdeApfsAESKeyWrap implements RFC 3394 AES Key Wrap.
func fdeApfsAESKeyWrap(kek, plaintext []byte) []byte {
	n := len(plaintext) / 8
	a := [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := make([][]byte, n)
	for i := range r {
		r[i] = make([]byte, 8)
		copy(r[i], plaintext[i*8:])
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		panic(err)
	}
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			b := make([]byte, 16)
			copy(b[:8], a[:])
			copy(b[8:], r[i])
			block.Encrypt(b, b)
			copy(a[:], b[:8])
			v := uint64(n*j + i + 1)
			for k := 7; k >= 0; k-- {
				a[k] ^= byte(v)
				v >>= 8
			}
			copy(r[i], b[8:])
		}
	}
	out := make([]byte, 8+len(plaintext))
	copy(out[:8], a[:])
	for i, rb := range r {
		copy(out[8+i*8:], rb)
	}
	return out
}

// fdeApfsEncryptBlock encrypts buf in-place using AES-128-XTS.
// The XTS tweak is the absolute sector number; block blockNum maps to sector
// blockNum * (apfsTestBlkSize / apfsTestSectorSz).
func fdeApfsEncryptBlock(buf, vek []byte, blockNum uint64) {
	c, err := xts.NewCipher(aes.NewCipher, vek)
	if err != nil {
		panic(err)
	}
	sectorNum := blockNum * (apfsTestBlkSize / apfsTestSectorSz)
	for i := 0; i < len(buf)/apfsTestSectorSz; i++ {
		s := buf[i*apfsTestSectorSz : (i+1)*apfsTestSectorSz]
		c.Encrypt(s, s, sectorNum+uint64(i))
	}
}

// fdeApfsLockerData serialises PBKDF2 parameters + wrappedKEK.
func fdeApfsLockerData(salt, wrappedKEK []byte) []byte {
	size := 2 + 2 + 4 + 2 + len(salt) + len(wrappedKEK)
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:2], apfsTestKDFType)
	binary.LittleEndian.PutUint32(b[4:8], apfsTestKDFIter)
	binary.LittleEndian.PutUint16(b[8:10], uint16(len(salt)))
	copy(b[10:], salt)
	copy(b[10+len(salt):], wrappedKEK)
	return b
}

// fdeApfsWriteEntry writes one keybag entry into buf at off, returns new off.
// Entries are 16-byte aligned per Apple's apfs-fuse reference; earlier
// versions used 8-byte alignment, which Apple's parser tolerated only by
// accident.
func fdeApfsWriteEntry(buf []byte, off, tag int, data []byte) int {
	const hLen = 24
	copy(buf[off:off+16], "test-uuid-000000")
	binary.LittleEndian.PutUint16(buf[off+16:], uint16(tag))
	binary.LittleEndian.PutUint16(buf[off+18:], uint16(len(data)))
	off += hLen
	copy(buf[off:], data)
	off += len(data)
	if rem := off % apfsTestKBEntryAlign; rem != 0 {
		off += apfsTestKBEntryAlign - rem
	}
	return off
}

// fdeApfsWriteKeybag fills the 4096-byte key bag block at buf with the
// Apple-shape layout: 32-byte obj_phys (type=0x6b657973 "syek") followed
// by 16-byte apfs_kb_locker header (version, nkeys, nbytes, padding) and
// 16-byte-aligned entries. Earlier versions used a 4-byte "kbag" magic
// at offset 0 of the block; that was wrong (no Apple container ever has
// it) and only worked because our matching reader checked for the same
// wrong magic.
func fdeApfsWriteKeybag(buf, salt, wrappedKEK, wrappedVEK []byte) {
	// obj_phys.type at +24 (cksum/oid/xid/subtype left zero — these
	// tests don't validate them).
	binary.LittleEndian.PutUint32(buf[24:28], apfsTestKBObjType)
	// apfs_kb_locker header at +32: version(2) + nkeys(2) + nbytes(4) + 8 bytes pad.
	binary.LittleEndian.PutUint16(buf[32:34], apfsTestKBVer)
	binary.LittleEndian.PutUint16(buf[34:36], 2) // nkeys
	off := apfsTestKBEntryArea
	off = fdeApfsWriteEntry(buf, off, apfsTestTagPass, fdeApfsLockerData(salt, wrappedKEK))
	fdeApfsWriteEntry(buf, off, apfsTestTagVEK, wrappedVEK)
}

// fdeBuildRawAPFSImage builds a 4-block synthetic APFS FDE container image.
// Block 0: NX superblock. Block 1: key bag. Block 2: payload (XTS-encrypted).
func fdeBuildRawAPFSImage(t *testing.T, passphrase, payload []byte) []byte {
	t.Helper()
	vek := fdeRand(32)
	salt := fdeRand(16)
	kek := pbkdf2.Key(passphrase, salt, apfsTestKDFIter, 32, sha256.New)
	wrappedVEK := fdeApfsAESKeyWrap(kek, vek)
	wrappedKEK := fdeApfsAESKeyWrap(kek, kek)
	img := make([]byte, 4*apfsTestBlkSize)
	copy(img[32:36], apfsTestNXMagic)
	binary.LittleEndian.PutUint32(img[36:40], apfsTestBlkSize)
	// nx_keylocker at offset 1296 (paddr=1, count=1).
	binary.LittleEndian.PutUint64(img[apfsTestNXKeylockerOff:apfsTestNXKeylockerOff+8], 1)
	binary.LittleEndian.PutUint64(img[apfsTestNXKeylockerOff+8:apfsTestNXKeylockerOff+16], 1)
	fdeApfsWriteKeybag(img[apfsTestBlkSize:], salt, wrappedKEK, wrappedVEK)
	payloadBlock := make([]byte, apfsTestBlkSize)
	if len(payload) > apfsTestBlkSize {
		payload = payload[:apfsTestBlkSize]
	}
	copy(payloadBlock, payload)
	fdeApfsEncryptBlock(payloadBlock, vek, 2)
	copy(img[2*apfsTestBlkSize:], payloadBlock)
	return img
}

// ── Tests: OpenLUKS ────────────────────────────────────────────────────────

func TestOpenLUKS_NotExist(t *testing.T) {
	_, err := OpenLUKS(filepath.Join(t.TempDir(), "nofile"), []byte("x"))
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestOpenLUKS_WrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	fdeBuildLUKS1ImageFile(t, path, []byte("correct"), fdeRand(32))
	_, err := OpenLUKS(path, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

// TestOpenLUKS_Success opens a LUKS1 image and exercises all Device methods.
func TestOpenLUKS_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	volumeKey := fdeRand(32)
	passphrase := []byte("correct horse battery staple")
	fdeBuildLUKS1ImageFile(t, path, passphrase, volumeKey)

	dev, err := OpenLUKS(path, passphrase)
	if err != nil {
		t.Fatalf("OpenLUKS: %v", err)
	}
	defer dev.Close()

	buf := make([]byte, 512)
	if _, err := dev.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if _, err := dev.WriteAt(buf, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if sz := dev.Size(); sz < 0 {
		t.Fatalf("Size: unexpected %d", sz)
	}
}

// ── Tests: OpenLUKSFrom ────────────────────────────────────────────────────

func TestOpenLUKSFrom_Error(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	fdeBuildLUKS1ImageFile(t, path, []byte("correct"), fdeRand(32))
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenLUKSFrom(f, []byte("wrong"))
	if err == nil {
		f.Close()
		t.Fatal("expected error for wrong passphrase")
	}
	f.Close()
}

func TestOpenLUKSFrom_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	passphrase := []byte("open from pass")
	fdeBuildLUKS1ImageFile(t, path, passphrase, fdeRand(32))
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenLUKSFrom(f, passphrase)
	if err != nil {
		f.Close()
		t.Fatalf("OpenLUKSFrom: %v", err)
	}
	defer dev.Close()
	buf := make([]byte, 512)
	if _, err := dev.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
}

// ── Tests: OpenAPFS ────────────────────────────────────────────────────────

func TestOpenAPFS_NotExist(t *testing.T) {
	_, err := OpenAPFS(filepath.Join(t.TempDir(), "nofile"), []byte("x"))
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestOpenAPFS_NotAPFS(t *testing.T) {
	p := filepath.Join(t.TempDir(), "random.img")
	if err := os.WriteFile(p, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenAPFS(p, []byte("pass"))
	if err == nil {
		t.Fatal("expected error for non-APFS image")
	}
}

func TestOpenAPFS_WrongPassphrase(t *testing.T) {
	img := fdeBuildRawAPFSImage(t, []byte("correct"), make([]byte, apfsTestSectorSz))
	path := filepath.Join(t.TempDir(), "apfs.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := OpenAPFS(path, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

// TestOpenAPFS_Success opens a synthetic APFS FDE image and exercises all
// Device methods, including verifying that Size returns 0.
func TestOpenAPFS_Success(t *testing.T) {
	payload := make([]byte, apfsTestSectorSz)
	copy(payload, []byte("apfs fde test payload"))
	passphrase := []byte("filevault passphrase")
	img := fdeBuildRawAPFSImage(t, passphrase, payload)
	path := filepath.Join(t.TempDir(), "apfs.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}

	dev, err := OpenAPFS(path, passphrase)
	if err != nil {
		t.Fatalf("OpenAPFS: %v", err)
	}
	defer dev.Close()

	buf := make([]byte, apfsTestSectorSz)
	if _, err := dev.ReadAt(buf, int64(2*apfsTestBlkSize)); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("decrypted content mismatch: got %q, want %q", buf[:20], payload[:20])
	}
	if _, err := dev.WriteAt(buf, int64(2*apfsTestBlkSize)); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if sz := dev.Size(); sz != 0 {
		t.Fatalf("apfsDevice.Size: want 0, got %d", sz)
	}
}

// ── Tests: OpenAPFSFrom ────────────────────────────────────────────────────

func TestOpenAPFSFrom_Error(t *testing.T) {
	img := fdeBuildRawAPFSImage(t, []byte("correct"), make([]byte, apfsTestSectorSz))
	path := filepath.Join(t.TempDir(), "apfs.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenAPFSFrom(f, []byte("wrong"))
	if err == nil {
		f.Close()
		t.Fatal("expected error for wrong passphrase")
	}
	f.Close()
}

func TestOpenAPFSFrom_Success(t *testing.T) {
	passphrase := []byte("open apfs from")
	img := fdeBuildRawAPFSImage(t, passphrase, make([]byte, apfsTestSectorSz))
	path := filepath.Join(t.TempDir(), "apfs.img")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenAPFSFrom(f, passphrase)
	if err != nil {
		f.Close()
		t.Fatalf("OpenAPFSFrom: %v", err)
	}
	defer dev.Close()
	buf := make([]byte, apfsTestSectorSz)
	if _, err := dev.ReadAt(buf, int64(2*apfsTestBlkSize)); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
}

// ── Tests: Create ──────────────────────────────────────────────────────────

func TestCreate_LUKS_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("create luks pass")
	dev, err := Create(LUKS, path, passphrase)
	if err != nil {
		t.Fatalf("Create(LUKS): %v", err)
	}
	want := make([]byte, 512)
	copy(want, []byte("create luks payload"))
	if _, err := dev.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	dev.Close()

	dev2, err := Open(LUKS, path, passphrase)
	if err != nil {
		t.Fatalf("Open(LUKS) after Create: %v", err)
	}
	defer dev2.Close()
	got := make([]byte, 512)
	if _, err := dev2.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Create(LUKS) roundtrip mismatch")
	}
}

func TestCreate_LUKS_Error(t *testing.T) {
	_, err := Create(LUKS, filepath.Join(t.TempDir(), "nofile"), []byte("x"))
	if err == nil {
		t.Fatal("expected error for nonexistent LUKS path")
	}
}

func TestCreate_APFS_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.apfs")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("create apfs pass")
	dev, err := Create(APFS, path, passphrase)
	if err != nil {
		t.Fatalf("Create(APFS): %v", err)
	}
	want := make([]byte, apfsTestSectorSz)
	copy(want, []byte("create apfs payload"))
	payloadOff := int64(2 * apfsTestBlkSize)
	if _, err := dev.WriteAt(want, payloadOff); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	dev.Close()

	dev2, err := Open(APFS, path, passphrase)
	if err != nil {
		t.Fatalf("Open(APFS) after Create: %v", err)
	}
	defer dev2.Close()
	got := make([]byte, apfsTestSectorSz)
	if _, err := dev2.ReadAt(got, payloadOff); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("Create(APFS) roundtrip mismatch")
	}
}

func TestCreate_APFS_Error(t *testing.T) {
	_, err := Create(APFS, filepath.Join(t.TempDir(), "nofile"), []byte("x"))
	if err == nil {
		t.Fatal("expected error for nonexistent APFS path")
	}
}

func TestCreate_UnknownType(t *testing.T) {
	_, err := Create(Type(99), filepath.Join(t.TempDir(), "x"), []byte("x"))
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

// ── Tests: CreateFrom ──────────────────────────────────────────────────────

func TestCreateFrom_LUKS_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("createfrom luks")
	dev, err := CreateFrom(LUKS, f, passphrase)
	if err != nil {
		f.Close()
		t.Fatalf("CreateFrom(LUKS): %v", err)
	}
	dev.Close()
}

func TestCreateFrom_LUKS_Error(t *testing.T) {
	_, err := CreateFrom(LUKS, &fdeFailRW{}, []byte("x"))
	if err == nil {
		t.Fatal("expected error when write fails")
	}
}

func TestCreateFrom_APFS_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.apfs")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("createfrom apfs")
	dev, err := CreateFrom(APFS, f, passphrase)
	if err != nil {
		f.Close()
		t.Fatalf("CreateFrom(APFS): %v", err)
	}
	dev.Close()
}

func TestCreateFrom_APFS_Error(t *testing.T) {
	_, err := CreateFrom(APFS, &fdeFailRW{}, []byte("x"))
	if err == nil {
		t.Fatal("expected error when write fails")
	}
}

func TestCreateFrom_UnknownType(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, err = CreateFrom(Type(99), f, []byte("x"))
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

// fdeFailRW is a minimal RW that always fails on WriteAt.
type fdeFailRW struct{}

func (*fdeFailRW) ReadAt(p []byte, off int64) (int, error) { return len(p), nil }
func (*fdeFailRW) WriteAt(p []byte, off int64) (int, error) {
	return 0, bytes.ErrTooLarge // any non-nil error
}
func (*fdeFailRW) Close() error { return nil }

// ── Tests: CLEAR ──────────────────────────────────────────────────────────

func TestOpenClear_NotExist(t *testing.T) {
	_, err := OpenClear(filepath.Join(t.TempDir(), "nofile"))
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestOpenClear_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	want := make([]byte, 512)
	copy(want, []byte("clear device test"))
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := OpenClear(path)
	if err != nil {
		t.Fatalf("OpenClear: %v", err)
	}
	defer dev.Close()
	if dev.Size() != 512 {
		t.Fatalf("Size: want 512, got %d", dev.Size())
	}
	got := make([]byte, 512)
	if _, err := dev.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("ReadAt mismatch")
	}
}

func TestOpenClearFrom_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenClearFrom(f)
	if err != nil {
		f.Close()
		t.Fatalf("OpenClearFrom: %v", err)
	}
	defer dev.Close()
	if dev.Size() != 512 {
		t.Fatalf("Size: want 512, got %d", dev.Size())
	}
}

func TestOpen_CLEAR_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	want := make([]byte, 512)
	copy(want, []byte("open clear via dispatcher"))
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(CLEAR, path, nil)
	if err != nil {
		t.Fatalf("Open(CLEAR): %v", err)
	}
	defer dev.Close()
	got := make([]byte, 512)
	if _, err := dev.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("ReadAt mismatch")
	}
}

func TestOpen_CLEAR_NotExist(t *testing.T) {
	_, err := Open(CLEAR, filepath.Join(t.TempDir(), "nofile"), nil)
	if err == nil {
		t.Fatal("expected error for nonexistent CLEAR path")
	}
}

func TestCreate_CLEAR_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Create(CLEAR, path, nil)
	if err != nil {
		t.Fatalf("Create(CLEAR): %v", err)
	}
	want := make([]byte, 512)
	copy(want, []byte("create clear payload"))
	if _, err := dev.WriteAt(want, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	dev.Close()

	dev2, err := Open(CLEAR, path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer dev2.Close()
	got := make([]byte, 512)
	if _, err := dev2.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestCreateFrom_CLEAR_Success(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := CreateFrom(CLEAR, f, nil)
	if err != nil {
		f.Close()
		t.Fatalf("CreateFrom(CLEAR): %v", err)
	}
	dev.Close()
}

// ── Tests: Detect ─────────────────────────────────────────────────────────

func TestDetect_LUKS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	fdeBuildLUKS1ImageFile(t, path, []byte("pass"), fdeRand(32))
	got, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != LUKS {
		t.Fatalf("Detect: want LUKS, got %d", got)
	}
}

func TestDetect_APFS(t *testing.T) {
	img := fdeBuildRawAPFSImage(t, []byte("pass"), make([]byte, apfsTestSectorSz))
	path := filepath.Join(t.TempDir(), "disk.apfs")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != APFS {
		t.Fatalf("Detect: want APFS, got %d", got)
	}
}

func TestDetect_CLEAR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Detect(path)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if got != CLEAR {
		t.Fatalf("Detect: want CLEAR, got %d", got)
	}
}

func TestDetect_NotExist(t *testing.T) {
	_, err := Detect(filepath.Join(t.TempDir(), "nofile"))
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestDetectFrom_LUKS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	fdeBuildLUKS1ImageFile(t, path, []byte("pass"), fdeRand(32))
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := DetectFrom(f)
	if err != nil {
		t.Fatalf("DetectFrom: %v", err)
	}
	if got != LUKS {
		t.Fatalf("DetectFrom: want LUKS, got %d", got)
	}
}

func TestDetectFrom_CLEAR(t *testing.T) {
	rw := &fdeZeroRW{}
	got, err := DetectFrom(rw)
	if err != nil {
		t.Fatalf("DetectFrom: %v", err)
	}
	if got != CLEAR {
		t.Fatalf("DetectFrom: want CLEAR, got %d", got)
	}
}

// ── Tests: Open with Auto ─────────────────────────────────────────────────

func TestOpen_Auto_LUKS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.luks")
	fdeBuildLUKS1ImageFile(t, path, []byte("autopass"), fdeRand(32))
	dev, err := Open(Auto, path, []byte("autopass"))
	if err != nil {
		t.Fatalf("Open(Auto) LUKS: %v", err)
	}
	dev.Close()
}

func TestOpen_Auto_APFS(t *testing.T) {
	img := fdeBuildRawAPFSImage(t, []byte("autopass"), make([]byte, apfsTestSectorSz))
	path := filepath.Join(t.TempDir(), "disk.apfs")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(Auto, path, []byte("autopass"))
	if err != nil {
		t.Fatalf("Open(Auto) APFS: %v", err)
	}
	dev.Close()
}

func TestOpen_Auto_CLEAR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := Open(Auto, path, nil)
	if err != nil {
		t.Fatalf("Open(Auto) CLEAR: %v", err)
	}
	dev.Close()
}

func TestOpen_Auto_NotExist(t *testing.T) {
	_, err := Open(Auto, filepath.Join(t.TempDir(), "nofile"), nil)
	if err == nil {
		t.Fatal("expected error for nonexistent path with Auto")
	}
}

func TestOpenFrom_Auto_CLEAR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.raw")
	if err := os.WriteFile(path, make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := OpenFrom(Auto, f, nil)
	if err != nil {
		f.Close()
		t.Fatalf("OpenFrom(Auto) CLEAR: %v", err)
	}
	dev.Close()
}

// fdeZeroRW is a minimal ReaderAt that always returns zeros.
type fdeZeroRW struct{}

func (*fdeZeroRW) ReadAt(p []byte, off int64) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
