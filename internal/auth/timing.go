package auth

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

const (
	calibrationSamples = 5
	safetyNumerator    = 5
	safetyDenominator  = 4
	jitterDivisor      = 4
	fallbackVerifyCost = 250 * time.Millisecond
)

var (
	calibrateOnce      sync.Once
	baselineVerifyCost time.Duration
)

func CalibrateVerifyCost() {
	calibrateOnce.Do(func() {
		encoded, err := HashPassword("calibration-probe-not-a-credential")
		if err != nil {
			baselineVerifyCost = fallbackVerifyCost
			return
		}

		var worst time.Duration
		for i := 0; i < calibrationSamples; i++ {
			start := time.Now()
			VerifyPassword("calibration-probe-mismatch", encoded)
			if elapsed := time.Since(start); elapsed > worst {
				worst = elapsed
			}
		}

		baselineVerifyCost = worst * safetyNumerator / safetyDenominator
		if baselineVerifyCost <= 0 {
			baselineVerifyCost = fallbackVerifyCost
		}
	})
}

func FailureDelayTarget() time.Duration {
	CalibrateVerifyCost()
	return baselineVerifyCost
}

func FailureJitter() time.Duration {
	span := int64(FailureDelayTarget() / jitterDivisor)
	if span <= 0 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return time.Duration(span / 2)
	}
	return time.Duration(n.Int64())
}
