//go:build !windows

package keys

import "syscall"

// oNoFollow makes OpenFile refuse to follow a final-component symlink. On a key
// path this stops freshly generated key material from being written through an
// attacker-planted symlink into another file.
const oNoFollow = syscall.O_NOFOLLOW
