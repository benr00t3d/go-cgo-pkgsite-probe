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
const ProbeVersion = "v0.0.140-sumd-capslock-checksum-route"

// OwnedBBaseline makes the independent researcher-owned B module a real
// dependency. With no published go.sum, B must be authenticated through the
// worker's effective checksum configuration before this package can compile.
const OwnedBBaseline = crosswritecanary.Baseline

// LTOValue keeps the bundled LTO object in cgo's link input.
func LTOValue() int { return int(C.lto_payload()) }
