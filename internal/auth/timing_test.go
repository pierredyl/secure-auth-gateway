package auth

import (
	"testing"
	"time"
)

func TestCalibrateVerifyCostExceedsSingleVerify(t *testing.T) {
	encoded, err := HashPassword("timing-test-password")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	start := time.Now()
	if _, err := VerifyPassword("timing-test-mismatch", encoded); err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	measured := time.Since(start)

	target := FailureDelayTarget()
	if target <= 0 {
		t.Fatalf("FailureDelayTarget() = %v, want > 0", target)
	}
	if target < measured {
		t.Errorf("FailureDelayTarget() = %v, want >= a real verify (%v)", target, measured)
	}
}

func TestFailureDelayTargetIsStable(t *testing.T) {
	first := FailureDelayTarget()
	for i := 0; i < 3; i++ {
		if got := FailureDelayTarget(); got != first {
			t.Fatalf("FailureDelayTarget() = %v on call %d, want stable %v", got, i, first)
		}
	}
}

func TestFailureJitterInRangeAndVaries(t *testing.T) {
	span := FailureDelayTarget() / jitterDivisor
	if span <= 0 {
		t.Fatalf("jitter span = %v, want > 0", span)
	}

	seen := make(map[time.Duration]struct{})
	for i := 0; i < 200; i++ {
		j := FailureJitter()
		if j < 0 || j >= span {
			t.Fatalf("FailureJitter() = %v, want within [0, %v)", j, span)
		}
		seen[j] = struct{}{}
	}

	if len(seen) < 2 {
		t.Errorf("FailureJitter() produced %d distinct value(s) over 200 draws, want varying output", len(seen))
	}
}
