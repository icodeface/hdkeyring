package hdkeyring

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/icodeface/hdkeyring/bip32"
	"github.com/tyler-smith/go-bip39"
	"math/big"
	"sync"
)

type Keyring struct {
	masterKey *bip32.Key
	seed      []byte
	stateLock sync.RWMutex
}

type KeyType = bip32.KeyType

const (
	KeyTypeECDSA   = bip32.KeyTypeECDSA
	KeyTypeEd25519 = bip32.KeyTypeEd25519
)

func NewKeyring(seed []byte, keyType KeyType) (*Keyring, error) {
	masterKey, err := bip32.NewMasterKey(seed, keyType)
	if err != nil {
		return nil, err
	}

	return &Keyring{
		masterKey: masterKey,
		seed:      seed,
	}, nil
}

// NewFromMnemonic returns a new Keyring from a BIP-39 mnemonic.
func NewFromMnemonic(mnemonic string, keyType KeyType) (*Keyring, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}

	seed, err := NewSeedFromMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}

	keyring, err := NewKeyring(seed, keyType)
	if err != nil {
		return nil, err
	}

	return keyring, nil
}

func (w *Keyring) DeriveKey(path DerivationPath) (*bip32.Key, error) {
	var err error
	key := w.masterKey
	for _, n := range path {
		key, err = key.NewChildKey(n)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

// DeriveECDSAPrivateKey derives the private key of the derivation path.
func (w *Keyring) DeriveECDSAPrivateKey(path DerivationPath) (*ecdsa.PrivateKey, error) {
	key, err := w.DeriveKey(path)
	if err != nil {
		return nil, err
	}

	pk := key.Key
	curve := btcec.S256()
	x, y := curve.ScalarBaseMult(pk)

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}
	return priv, nil
}

// DeriveECDSAPublicKey derives the public key of the derivation path.
func (w *Keyring) DeriveECDSAPublicKey(path DerivationPath) (*ecdsa.PublicKey, error) {
	privateKeyECDSA, err := w.DeriveECDSAPrivateKey(path)
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyECDSA.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}

	return publicKeyECDSA, nil
}

func ECDSAPrivateKeyBytes(privateKey *ecdsa.PrivateKey) []byte {
	return crypto.FromECDSA(privateKey)
}

func ECDSAPublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	return crypto.FromECDSAPub(pub)
}

// DeriveEd25519PrivateKey derives the private key of the derivation path.
func (w *Keyring) DeriveEd25519PrivateKey(path DerivationPath) (*ed25519.PrivateKey, error) {
	key, err := w.DeriveKey(path)
	if err != nil {
		return nil, err
	}

	priv := ed25519.NewKeyFromSeed(key.Key)
	return &priv, nil
}

// DeriveEd25519PublicKey derives the private key of the derivation path.
func (w *Keyring) DeriveEd25519PublicKey(path DerivationPath) (ed25519.PublicKey, error) {
	privateKeyEd25519, err := w.DeriveEd25519PrivateKey(path)
	if err != nil {
		return nil, err
	}

	publicKey := privateKeyEd25519.Public()
	publicKeyEd25519, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}
	return publicKeyEd25519, nil
}

// NewMnemonic returns a randomly generated BIP-39 mnemonic using 128-256 bits of entropy.
func NewMnemonic(bits int) (string, error) {
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// NewSeedFromMnemonic returns a BIP-39 seed based on a BIP-39 mnemonic.
func NewSeedFromMnemonic(mnemonic string) ([]byte, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	return bip39.NewSeedWithErrorChecking(mnemonic, "")
}
