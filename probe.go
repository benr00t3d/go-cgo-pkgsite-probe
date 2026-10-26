package pkgsiteprobe

/*
#cgo linux,amd64 CFLAGS: -target x86_64-codex/poc-linux-gnu
*/
import "C"

// Present is a harmless exported symbol for documentation indexing.
const Present = true

// ProbeVersion forces a fresh package-analysis input for this bounded run.
const ProbeVersion = "v0.0.6-codex"
