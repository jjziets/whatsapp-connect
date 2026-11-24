//go:build !darwin

package securestore

func NewNativeKeyStore() KeyStore { return nil }
