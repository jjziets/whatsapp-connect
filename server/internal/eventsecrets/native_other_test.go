//go:build !darwin

package eventsecrets

import (
	"errors"
	"testing"
)

func TestUnsupportedNativePlatformFailsClosed(t *testing.T) {
	if _, e := Native(profileA); !errors.Is(e, ErrUnsupported) {
		t.Fatal("native credential fallback on unsupported OS")
	}
}
