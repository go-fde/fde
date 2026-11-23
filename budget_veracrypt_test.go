package fde

// WithBudget reaches the VeraCrypt backend. The fixture is a VeraCrypt volume
// with PBKDF2-SHA-512 at 500,000 iterations; a trial with PIM 0 charges the
// KDFs before it in cryptsetup's order, then the one that opens it.

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/go-encryptions/kdfbudget"
	"github.com/go-fde/veracrypt"
)

// Per KDF: output blocks of the 192-byte key x 2 x hash cost x iterations.
const veracryptDerivation = 10*2*1*2000 + // RIPEMD-160, TrueCrypt, 2000
	10*2*1*1000 + // RIPEMD-160, TrueCrypt, 1000
	3*2*2*1000 + // SHA-512, TrueCrypt, 1000
	3*2*4*1000 + // Whirlpool, TrueCrypt, 1000
	3*2*2*500000 // SHA-512, VeraCrypt: the one that opens the fixture

func veracryptBudget(work uint64) *kdfbudget.Budget {
	b := kdfbudget.Unlimited()
	b.MaxWork = work
	return b
}

// TestOpenVeraCrypt_BudgetRefusesAndAccepts: through every entry point a
// budget one unit short is refused with ErrLimit, one of exactly the trial's
// cost opens the volume and is spent to the unit.
func TestOpenVeraCrypt_BudgetRefusesAndAccepts(t *testing.T) {
	path := decompressFixture(t, veracryptFixture)
	img, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pw := []byte(veracryptPassword)
	open := map[string]func(b *kdfbudget.Budget) (Device, error){
		"OpenVeraCrypt":   func(b *kdfbudget.Budget) (Device, error) { return OpenVeraCrypt(path, pw, WithBudget(b)) },
		"Open(VERACRYPT)": func(b *kdfbudget.Budget) (Device, error) { return Open(VERACRYPT, path, pw, WithBudget(b)) },
		"OpenVeraCryptFrom": func(b *kdfbudget.Budget) (Device, error) {
			return OpenVeraCryptFrom(sizedRW{bytes.NewReader(img)}, pw, WithBudget(b))
		},
		"OpenFrom(VERACRYPT)": func(b *kdfbudget.Budget) (Device, error) {
			return OpenFrom(VERACRYPT, sizedRW{bytes.NewReader(img)}, pw, WithBudget(b))
		},
	}
	for name, f := range open {
		t.Run(name, func(t *testing.T) {
			_, err := f(veracryptBudget(veracryptDerivation - 1))
			if !errors.Is(err, kdfbudget.ErrLimit) || !errors.Is(err, veracrypt.ErrLimit) || errors.Is(err, veracrypt.ErrWrongSecret) {
				t.Fatalf("a budget one unit short: err = %v, want ErrLimit", err)
			}
			b := veracryptBudget(veracryptDerivation)
			// The refusal above is cheap (the 500,000-iteration derivation is
			// skipped); a successful open costs it in full, which under -race
			// on arm64 is minutes. Two entry points, one path and one stream,
			// open; the others only prove the option arrives.
			if name != "OpenVeraCrypt" && name != "OpenFrom(VERACRYPT)" {
				return
			}
			dev, err := f(b)
			if err != nil {
				t.Fatalf("a budget of exactly the trial refused: %v", err)
			}
			dev.Close()
			if got := b.Spent(); got != veracryptDerivation {
				t.Fatalf("spent %d, want %d", got, veracryptDerivation)
			}
		})
	}
}

// TestOpenVeraCrypt_DefaultBudgetAcceptsNormalVolume: no option is a fresh
// default budget, which a normal volume fits every time.
func TestOpenVeraCrypt_DefaultBudgetAcceptsNormalVolume(t *testing.T) {
	path := decompressFixture(t, veracryptFixture)
	dev, err := OpenVeraCrypt(path, []byte(veracryptPassword))
	if err != nil {
		t.Fatal(err)
	}
	dev.Close()
}
