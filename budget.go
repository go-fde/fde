package fde

import "github.com/go-encryptions/kdfbudget"

// maxArgon2Threads is the most Argon2 lanes the facade lets one unlock ask
// for by default: cryptsetup writes 1 to 4 (crypt_pbkdf_get_limits), and the
// APFS backend would otherwise take up to 255.
const maxArgon2Threads = 4

// Option adjusts how the Open functions unlock a volume.
type Option func(*config)

type config struct {
	budget *kdfbudget.Budget
}

// WithBudget makes an unlock charge its key-derivation work to b instead of a
// default budget. The LUKS, APFS and BitLocker backends charge every
// derivation to b before it runs, and refuse the volume with an error that
// matches kdfbudget.ErrLimit (also luks.ErrLimit, apfs.ErrLimit and
// bitlocker.ErrLimit) when the total, an Argon2 run's memory or its threads
// exceed b.
//
// A Budget is spent as it is used: one shared by several Open calls caps their
// sum, so give each unlock its own to cap each one. kdfbudget.Unlimited() is
// for a volume you trust. The VeraCrypt backend does not take a budget yet and
// ignores it.
func WithBudget(b *kdfbudget.Budget) Option {
	return func(c *config) { c.budget = b }
}

// newConfig applies opts. Without WithBudget each unlock gets a fresh
// kdfbudget.Default() whose Argon2 threads are capped at maxArgon2Threads.
func newConfig(opts []Option) config {
	var c config
	for _, o := range opts {
		o(&c)
	}
	if c.budget == nil {
		c.budget = kdfbudget.Default()
		c.budget.MaxThreads = maxArgon2Threads
	}
	return c
}
