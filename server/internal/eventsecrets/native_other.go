//go:build !darwin

package eventsecrets

// Native has no file, environment, or in-memory production fallback.
func Native(profileID string) (EventSecretProvider, error) { return nil, ErrUnsupported }
