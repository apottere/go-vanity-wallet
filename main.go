package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"github.com/apottere/go-vanity-wallet/utils"
	"github.com/dustinxie/ecc"
	"github.com/wealdtech/go-merkletree/keccak256"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
	"os"
	"strconv"
	"strings"
)

func fatal(a ...any) {
	_, err := fmt.Fprintln(os.Stderr, a...)
	if err != nil {
		panic(err)
	}

	os.Exit(1)
}

type DerivationPart struct {
	last       bool
	i          uint64
	serialized []byte
}

const hardenedLimit = 0x80000000
var seedSalt = []byte("mnemonic")
var masterKeySeed = []byte("Bitcoin seed")

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fatal("usage: vanity-wallet <entropy> [derivation path]")
	}

	entropyString := args[0]
	entropyInt, err := strconv.Atoi(entropyString)
	if err != nil {
		fatal("invalid entropy:", entropyString)
	}

	if entropyInt < 128 || entropyInt > 256 || entropyInt%32 != 0 {
		fatal("entropy must be a multiple of 32 between 128 and 256 (inclusive)")
	}

	derivationString := args[1]
	derivationStringArray := strings.Split(derivationString, "/")
	if len(derivationStringArray) < 2 || derivationStringArray[0] != "m" {
		fatal("invalid derivation path:", derivationString)
	}

	derivationLength := len(derivationStringArray) - 1
	derivation := make([]DerivationPart, derivationLength)
	for i, part := range derivationStringArray[1:] {
		hardened := strings.HasSuffix(part, "'")
		if hardened {
			part = strings.TrimSuffix(part, "'")
		}

		index, err := strconv.ParseUint(part, 10, 0)
		if err != nil {
			fatal("invalid derivation part:", part)
		}

		if hardened {
			index += hardenedLimit
		}

		serialized := make([]byte, 4)
		serialized[0] = byte(index >> 24)
		serialized[1] = byte(index >> 16)
		serialized[2] = byte(index >> 8)
		serialized[3] = byte(index)
		derivation[i] = DerivationPart{
			last:       i == derivationLength-1,
			i:          index,
			serialized: serialized,
		}
	}

	derivationStringOut := ""
	for i, part := range derivation {
		if i > 0 {
			derivationStringOut += " "
		}
		derivationStringOut += fmt.Sprintf("0x%X", part.serialized)
	}

	entropy := utils.NewEntropyInfo(entropyInt)

	fmt.Println("Mnemonic Length:", entropy.MnemonicWordCount)
	fmt.Println("Derivation Path:", derivationStringOut)

	p256k1 := ecc.P256k1()
	n := p256k1.Params().N

	// Generate random mnemonic
	mnemonic, err := utils.RandomMnemonic(entropy)
	if err != nil {
		panic(err)
	}

	fmt.Println("Random Mnemonic:", string(mnemonic))

	// Create seed from mnemonic
	seed := pbkdf2.Key(mnemonic, seedSalt, 2048, 64, sha512.New)
	hash := hmac.New(sha512.New, masterKeySeed)
	hash.Write(seed)
	I := hash.Sum(nil)
	privateKeyBytes := I[:32]
	privateKey := new(big.Int).SetBytes(privateKeyBytes)
	chainCode := I[32:]

	// Derive private key
	for _, part := range derivation {
		hash = hmac.New(sha512.New, chainCode)
		if part.i >= hardenedLimit {
			hash.Write([]byte{0})
			hash.Write(privateKeyBytes)
			hash.Write(part.serialized)
			I = hash.Sum(nil)
		} else {
			x, y := p256k1.ScalarBaseMult(privateKeyBytes)
			hash.Write([]byte{byte(2 + y.Bit(0))})
			hash.Write(x.FillBytes(make([]byte, 32)))
			hash.Write(part.serialized)
			I = hash.Sum(nil)
		}

		parsedLeft := new(big.Int).SetBytes(I[:32])
		newPrivateKey := new(big.Int).Add(parsedLeft, privateKey)
		privateKey = new(big.Int).Mod(newPrivateKey, n)
		if privateKey.Cmp(big.NewInt(0)) == 0 || privateKey.Cmp(n) != -1 {
			panic("invalid private key!") // TODO: skip this mnemonic and try again
		}

		privateKeyBytes = privateKey.FillBytes(make([]byte, 32))
		chainCode = I[32:]
	}

	// Derive address
	x, y := p256k1.ScalarBaseMult(privateKeyBytes)
	keccak := keccak256.New()
	publicKey := make([]byte, 64)
	x.FillBytes(publicKey[:32])
	y.FillBytes(publicKey[32:])
	address := keccak.Hash(publicKey)[12:]
	fmt.Printf("Address: 0x%x\n", address)

	// TODO: optimize
	// TODO: loop
	// TODO: check public key for vanity
}
