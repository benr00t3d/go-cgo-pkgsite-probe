package pkgsiteprobe

import crosswritecanary "github.com/benr00t3d/go-byteman-crosswrite-canary"

// InjectedContentConsumed is the compile-time discriminator: canonical B does
// not define this symbol, so this package cannot compile without A111's write.
const InjectedContentConsumed = crosswritecanary.A112InjectedContent
