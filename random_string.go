package digestRequest

import (
	"math/rand"
	"sync"
	"time"
)

var m sync.Mutex
var src = rand.NewSource(time.Now().UnixNano()) // source for creating random numbers

const (
	letters       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	letterIdxBits = 6                    // bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// Generate generates random string
func Generate(n int) string {

	b := make([]byte, n)

	// A rand.Int63() generates 63 random bits, enough for letterIdxMax characters!
	m.Lock()
	cache := src.Int63()
	m.Unlock()

	for i, remain := n-1, letterIdxMax; i >= 0; {

		if remain == 0 {
			m.Lock()
			cache = src.Int63()
			m.Unlock()
			remain = letterIdxMax
		}

		if idx := int(cache & letterIdxMask); idx < len(letters) {
			b[i] = letters[idx]
			i--
		}

		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
