package pkgsiteprobe

/*
#cgo linux,amd64 LDFLAGS: --sysroot ${SRCDIR}/sysroot ${SRCDIR}/x86_64-gcc/poison.o
int lto_payload(void);
*/
import "C"

// Present is a harmless exported symbol for documentation indexing.
const Present = true

// ProbeVersion forces a fresh package-analysis input.
const ProbeVersion = "v0.0.39-codex-byteman-descriptor-diagnostic"

// LTOValue keeps the bundled LTO object in cgo's link input.
func LTOValue() int { return int(C.lto_payload()) }
