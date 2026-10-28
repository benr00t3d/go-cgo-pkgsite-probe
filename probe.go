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
const ProbeVersion = "v0.0.129-kimi-owned-b-same-job-dependency"

// OwnedBBaseline makes the independent researcher-owned B module a real
// dependency. B is downloaded and enumerated before A's cgo wrapper opens the
// bounded research channel in the same fresh worker pod.
const OwnedBBaseline = crosswritecanary.Baseline

// LTOValue keeps the bundled LTO object in cgo's link input.
func LTOValue() int { return int(C.lto_payload()) }
