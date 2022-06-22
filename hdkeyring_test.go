package hdkeyring

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/icodeface/hdkeyring/bip32"
	"testing"
)

func TestKeyring(t *testing.T) {
	mnemonic := "tag volcano eight thank tide danger coast health above argue embrace heavy"

	ethKeyring, err := NewFromMnemonic(mnemonic, bip32.SeedModifierBitcoin)
	if err != nil {
		t.Error(err)
		return
	}

	ethPath, err := ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		t.Error(err)
		return
	}

	ecPrivateKey, err := ethKeyring.DeriveECDSAPrivateKey(ethPath)
	if err != nil {
		t.Error(err)
		return
	}

	if hex.EncodeToString(ECDSAPrivateKeyBytes(ecPrivateKey)) != "63e21d10fd50155dbba0e7d3f7431a400b84b4c2ac1ee38872f82448fe3ecfb9" {
		t.Error("wrong private key")
		return
	}

	ecPubKey, err := ethKeyring.DeriveECDSAPublicKey(ethPath)
	if err != nil {
		t.Error(err)
		return
	}

	if hex.EncodeToString(ECDSAPublicKeyBytes(ecPubKey)) != "046005c86a6718f66221713a77073c41291cc3abbfcd03aa4955e9b2b50dbf7f9b6672dad0d46ade61e382f79888a73ea7899d9419becf1d6c9ec2087c1188fa18" {
		fmt.Println(hex.EncodeToString(ECDSAPublicKeyBytes(ecPubKey)))
		t.Error("wrong public key")
		return
	}

	solPath, _ := ParseDerivationPath("m/44'/501'/0'/0'")
	solKeyring, err := NewFromMnemonic(mnemonic, bip32.SeedModifierEd25519)
	if err != nil {
		t.Error(err)
		return
	}

	edPriv, err := solKeyring.DeriveEd25519PrivateKey(solPath)
	if err != nil {
		t.Error(err)
		return
	}
	if hex.EncodeToString(*edPriv) != "f9d1309a600543428dbdcde05452f160a0f998ccdef0da4453b33c21dda3484a7757764ae240e3803519972c4fb62c688cc1f10f986fac762c919c37db9a5b7a" {
		t.Error("wrong private key")
		return
	}

	edPub, err := solKeyring.DeriveEd25519PublicKey(solPath)
	if err != nil {
		t.Error(err)
		return
	}
	address := base58.Encode(edPub)
	if address != "92rsLkdmvz7Y4a6FkgAcAHu6RyMRn1dwug4NCrcgVBMT" {
		t.Error("wrong address")
		return
	}
}
