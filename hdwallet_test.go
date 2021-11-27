package hdwallet

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestWallet(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"
	wallet, err := NewFromMnemonic(mnemonic)
	if err != nil {
		t.Error(err)
	}

	path, err := ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		t.Error(err)
	}

	privateKey, err := wallet.DerivePrivateKey(path)
	if err != nil {
		t.Error(err)
	}

	if hex.EncodeToString(PrivateKeyBytes(privateKey)) != "63e21d10fd50155dbba0e7d3f7431a400b84b4c2ac1ee38872f82448fe3ecfb9" {
		t.Error("wrong private key")
	}

	pubKey, err := wallet.DerivePublicKey(path)
	if err != nil {
		t.Error(err)
	}

	if hex.EncodeToString(PublicKeyBytes(pubKey)) != "046005c86a6718f66221713a77073c41291cc3abbfcd03aa4955e9b2b50dbf7f9b6672dad0d46ade61e382f79888a73ea7899d9419becf1d6c9ec2087c1188fa18" {
		fmt.Println(hex.EncodeToString(PublicKeyBytes(pubKey)))
		t.Error("wrong public key")
	}
}
