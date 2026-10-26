package pkgsiteprobe

/*
#cgo linux,amd64 CFLAGS: -fno-canonical-system-headers
*/
import "C"

// Present is a harmless exported symbol for documentation indexing.
const Present = true

// ProbeVersion forces a fresh package-analysis input for this bounded run.
const ProbeVersion = "v0.0.9-codex"
