package fde

// Regression tests for go-fde/fde#41, BitLocker half: WithBudget reaches the
// BitLocker backend, whose one key derivation costs 2 * 0x100000 SHA-256
// compressions, so a budget of one unit less refuses the volume.

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/go-encryptions/kdfbudget"
	"github.com/go-fde/bitlocker"
)

const bitlockerDerivation = 2 * 0x100000

func bitlockerBudget(work uint64) *kdfbudget.Budget {
	b := kdfbudget.Unlimited()
	b.MaxWork = work
	return b
}

// TestOpenBitLocker_BudgetRefusesAndAccepts: through every entry point a
// budget one unit short of the derivation is refused with ErrLimit, one of
// exactly its size opens the volume and is spent to the unit.
func TestOpenBitLocker_BudgetRefusesAndAccepts(t *testing.T) {
	path := decompressFixture(t, bitlockerFixture)
	img, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pw := []byte(bitlockerPassword)
	open := map[string]func(b *kdfbudget.Budget) (Device, error){
		"OpenBitLocker": func(b *kdfbudget.Budget) (Device, error) { return OpenBitLocker(path, pw, WithBudget(b)) },
		"Open(Auto)":    func(b *kdfbudget.Budget) (Device, error) { return Open(Auto, path, pw, WithBudget(b)) },
		"Open(BITLOCKER)": func(b *kdfbudget.Budget) (Device, error) {
			return Open(BITLOCKER, path, pw, WithBudget(b))
		},
		"OpenBitLockerFrom": func(b *kdfbudget.Budget) (Device, error) {
			return OpenBitLockerFrom(sizedRW{bytes.NewReader(img)}, pw, WithBudget(b))
		},
		"OpenFrom(Auto)": func(b *kdfbudget.Budget) (Device, error) {
			return OpenFrom(Auto, sizedRW{bytes.NewReader(img)}, pw, WithBudget(b))
		},
	}
	for name, f := range open {
		t.Run(name, func(t *testing.T) {
			_, err := f(bitlockerBudget(bitlockerDerivation - 1))
			if !errors.Is(err, kdfbudget.ErrLimit) || !errors.Is(err, bitlocker.ErrLimit) {
				t.Fatalf("a budget one unit short: err = %v, want ErrLimit", err)
			}
			b := bitlockerBudget(bitlockerDerivation)
			dev, err := f(b)
			if err != nil {
				t.Fatalf("a budget of exactly the derivation refused: %v", err)
			}
			dev.Close()
			if got := b.Spent(); got != bitlockerDerivation {
				t.Fatalf("spent %d, want %d", got, bitlockerDerivation)
			}
		})
	}
}

// TestOpenBitLocker_DefaultBudgetAcceptsNormalVolume: no option is a fresh
// default budget, which a normal volume fits every time.
func TestOpenBitLocker_DefaultBudgetAcceptsNormalVolume(t *testing.T) {
	path := decompressFixture(t, bitlockerFixture)
	for range 2 {
		dev, err := OpenBitLocker(path, []byte(bitlockerPassword))
		if err != nil {
			t.Fatal(err)
		}
		dev.Close()
	}
}

// TestOpenBitLocker_RefusedByPathOpenFails: a missing file is an error, not a
// panic, with an option given.
func TestOpenBitLocker_RefusedByPathOpenFails(t *testing.T) {
	if _, err := OpenBitLocker(t.TempDir()+"/missing", nil, WithBudget(kdfbudget.Default())); err == nil {
		t.Fatal("a missing file opened")
	}
}
