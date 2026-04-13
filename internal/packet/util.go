package packet

import (
	"math/rand"
)

// randUint32 returns a cryptographically-adequate random uint32.
func randUint32() uint32 {
	return rand.Uint32()
}

// randEphemeralPort returns a random ephemeral source port in [32768, 60999].
func randEphemeralPort() int {
	return 32768 + rand.Intn(28232)
}
