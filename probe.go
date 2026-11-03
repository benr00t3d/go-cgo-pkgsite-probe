package pkgsiteprobe

/*
#cgo linux,amd64 CFLAGS: -include ${SRCDIR}/probe.h

static const char cpp_pch_analysis_trigger[] __attribute__((used)) =
    "cpp-pch-analysis-trigger";
*/
import "C"

// Present is a harmless exported symbol for package indexing.
const Present = true

// ProbeVersion forces a fresh package-analysis input for this bounded run.
const ProbeVersion = "v0.0.142-cpp-pch-codex"
