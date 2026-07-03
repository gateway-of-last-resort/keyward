//go:build windows

package keys

// oNoFollow is a no-op on Windows: syscall has no O_NOFOLLOW and the symlink
// threat model differs. The O_EXCL path still guards new-key creation.
const oNoFollow = 0
