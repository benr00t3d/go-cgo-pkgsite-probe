package pkgsiteprobe

/*
#cgo linux,amd64 CFLAGS: --sysroot ${SRCDIR}/sysroot
*/
import "C"

// Present is a harmless exported symbol for documentation indexing.
const Present = true

// ProbeVersion forces a fresh package-analysis input.
const ProbeVersion = "v0.0.13-codex"
