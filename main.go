package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"github.com/apottere/go-vanity-wallet/utils"
	"github.com/dustinxie/ecc"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"hash"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

func loop(wg *sync.WaitGroup, entropyInt int, derivation []DerivationPart) {
	defer wg.Done()
	entropy := utils.NewEntropyInfo(entropyInt)

	// Shared vars
	var err error
	var mnemonic []byte
	var seed []byte
	var currentHash hash.Hash
	var I []byte
	var chainCode []byte
	var privateKeyBytes []byte
	var x, y *big.Int

	p256k1 := ecc.P256k1()
	n := p256k1.Params().N
	keccak := sha3.NewLegacyKeccak256()
	zero := big.NewInt(0)
	zeroByte := []byte{0}
	bytePrefix := []byte{0}
	privateKey := new(big.Int)
	newPrivateKey := new(big.Int)
	publicKey := make([]byte, 64)
	publicKeyLeft := publicKey[:32]
	publicKeyRight := publicKey[32:]
	tempIntBytes := make([]byte, 32)
	skip := false
	var count uint64 = 0

	for {
		// Generate random mnemonic
		mnemonic, err = utils.RandomMnemonic(entropy)
		if err != nil {
			panic(err)
		}

		// Create seed from mnemonic
		seed = pbkdf2.Key(mnemonic, seedSalt, 2048, 64, sha512.New)
		currentHash = hmac.New(sha512.New, masterKeySeed)
		currentHash.Write(seed)
		I = currentHash.Sum(nil)
		privateKeyBytes = I[:32]
		privateKey.SetBytes(privateKeyBytes)
		chainCode = I[32:]

		// Derive private key
		skip = false
		for _, part := range derivation {
			currentHash = hmac.New(sha512.New, chainCode)
			if part.i >= hardenedLimit {
				currentHash.Write(zeroByte)
				currentHash.Write(privateKeyBytes)
				currentHash.Write(part.serialized)
				I = currentHash.Sum(nil)
			} else {
				x, y := p256k1.ScalarBaseMult(privateKeyBytes)
				bytePrefix[0] = 2 + byte(y.Bit(0))
				currentHash.Write(bytePrefix)
				currentHash.Write(x.FillBytes(tempIntBytes))
				currentHash.Write(part.serialized)
				I = currentHash.Sum(nil)
			}

			newPrivateKey.SetBytes(I[:32])
			newPrivateKey.Add(newPrivateKey, privateKey)
			privateKey.Mod(newPrivateKey, n)
			if privateKey.Cmp(zero) == 0 || privateKey.Cmp(n) != -1 {
				fmt.Println("Private key is invalid, skipping!")
				skip = true
				break
			}

			privateKeyBytes = privateKey.FillBytes(tempIntBytes)
			chainCode = I[32:]
		}
		count += 1
		if skip {
			continue
		}

		// Derive address
		x, y = p256k1.ScalarBaseMult(privateKeyBytes)
		x.FillBytes(publicKeyLeft)
		y.FillBytes(publicKeyRight)
		keccak.Reset()
		keccak.Write(publicKey)
		address := keccak.Sum(nil)[12:]

		if address[0] == 0x1b && address[1] == 0x0 && address[2] == 0x0 {
			result := fmt.Sprintf("0x%x", address)
			result += "\t" + string(mnemonic)
			fmt.Println(result)
		}
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fatal("usage: vanity-wallet <entropy> [derivation path]")
	}

	threadsString := args[0]
	threads, err := strconv.Atoi(threadsString)
	if err != nil {
		fatal("invalid thread count:", threadsString)
	}
	if threads < 1 {
		threads = runtime.NumCPU()
		fmt.Printf("Threads: %d\n", threads)
	}
	if threads > 10 {
		runtime.GOMAXPROCS(threads)
	}

	entropyString := args[1]
	entropyInt, err := strconv.Atoi(entropyString)
	if err != nil {
		fatal("invalid entropy:", entropyString)
	}

	if entropyInt < 128 || entropyInt > 256 || entropyInt%32 != 0 {
		fatal("entropy must be a multiple of 32 between 128 and 256 (inclusive)")
	}

	derivationString := args[2]
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

	fmt.Println("Derivation Path:", derivationStringOut)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go loop(&wg, entropyInt, derivation)
	}
	wg.Wait()
}
