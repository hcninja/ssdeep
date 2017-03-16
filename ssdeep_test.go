package ssdeep

import (
	"bytes"
	"testing"
)

func TestRollingHash(t *testing.T) {
	sdeep := NewSSDEEP()
	if sdeep.rollHash(byte('A')) != 585 {
		t.Error("Rolling hash not matching")
	}
}

func TestLevenshteinDistance(t *testing.T) {
	d := LevenshteinDistance("kitten", "sitting")
	if d != 3 {
		t.Errorf("Invalid edit distance: %d", d)
	}
}

func TestSSDEEP(t *testing.T) {
	tests := map[string]string{
		"This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message": "6:hGcpLGcpLGcpLGcpLGcpLGcpLGcpLGcpLGcD:h55555555D",
		"This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message..........................":                       "3:hXSVs5XDsHVs5XDsHVs5XDsHVs5XDsHVs5XDsHVs5XDsHVuXXXXXXL:hVtsHytsHytsHytsHytsHytsHwr",
		"This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message, This is a test message":                                                 "4:hVsHdEVVsHdEVVsHdEVVsHdEVVsHdEVVsHdEVVsHdU:M9393939393939U",
		"This is a test message,": "1:xNMWFMWFEFRAWRFIAWWECAJn:4W2W+UW0AWWECAJ",
	}

	for k, v := range tests {
		buff := bytes.NewBufferString(k)

		sdeep := NewSSDEEP()
		sdeep.Fuzzy(buff)

		got := sdeep.String()

		t.Logf(got)

		if v != got {
			t.Errorf("Expected: %s; Got: %s", v, got)
		}
	}
}

func TestSSDEEPScore(t *testing.T) {
	score := 94
	tests := []string{
		"This is a test message",
		"This is another test message",
	}

	var fuzz []string
	for _, v := range tests {
		buff := bytes.NewBufferString(v)

		sdeep := NewSSDEEP()
		sdeep.Fuzzy(buff)

		got := sdeep.String()
		t.Logf(got)
		fuzz = append(fuzz, got)
	}

	sab, err := HashDistance(fuzz[0], fuzz[1])
	if err != nil {
		t.Error(err)
	}

	t.Logf("Match percent: %d%%", sab)

	if sab != score {
		t.Error("Score should be %d and got %d", sab, score)
	}
}
