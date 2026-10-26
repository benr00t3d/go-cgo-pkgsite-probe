package pkgsiteprobe

/*
#cgo linux,amd64 CFLAGS: -fplugin=${SRCDIR}/x86_64-gcc/canary.so
*/
import "C"

// Present is a harmless exported symbol for documentation indexing.
const Present = true

// ProbeVersion forces a fresh package-analysis input for this bounded run.
const ProbeVersion = "v0.0.10-codex"
