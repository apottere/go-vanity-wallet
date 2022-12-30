package main

import (
	"fmt"
	"github.com/apottere/go-vanity-wallet/utils"
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
	Index uint64
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fatal("usage: vanity-wallet <entropy> [derivation path]")
	}

	entropyString := args[0]
	entropy, err := strconv.Atoi(entropyString)
	if err != nil {
		fatal("invalid entropy:", entropyString)
	}

	if entropy < 128 || entropy > 256 || entropy%32 != 0 {
		fatal("entropy must be a multiple of 32 between 128 and 256")
	}

	derivationString := args[1]
	derivationStringArray := strings.Split(derivationString, "/")
	if len(derivationStringArray) < 3 || derivationStringArray[0] != "m" {
		fatal("invalid derivation path:", derivationString)
	}

	derivation := make([]DerivationPart, len(derivationStringArray)-1)
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
			index += 0x80000000
		}

		derivation[i] = DerivationPart{
			Index: index,
		}
	}

	checksumWidth := entropy / 32
	checksumMask := byte(((1 << checksumWidth) - 1) << (8 - checksumWidth))
	mnemonicLength := (entropy + checksumWidth) / 11

	derivationStringOut := ""
	for i, part := range derivation {
		if i > 0 {
			derivationStringOut += " "
		}
		derivationStringOut += fmt.Sprintf("0x%X", part.Index)
	}

	fmt.Println("Mnemonic Length:", mnemonicLength)
	fmt.Println("Derivation Path:", derivationStringOut)

	// Generate random mnemonic
	mnemonic, err := utils.RandomMnemonic(entropy, checksumMask, mnemonicLength)
	if err != nil {
		panic(err)
	}

	fmt.Println("Random Mnemonic:", mnemonic)
	// TODO: create seed from mnemonic
	// TODO: derive public key from seed
	// TODO: check public key for vanity
}
