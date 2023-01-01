# Golang Vanity Wallet

## Features
* Generates mnemonics for an HD wallet, not just a single private key
* Configurable number of threads (defaults to 2 * number of cores)
* Configurable entropy from 128-256 bits
* Configurable derivation path (ETH/Metamask default: `m/44'/60'/0'/0/0`)

## Development

```
go run main.go -1 256 "m/44'/60'/0'/0/0"
```

## Build

```
GOOS=darwin GOARCH=amd64 go build -o ./bin/vanity-wallet-darwin-amd64
GOOS=linux GOARCH=amd64 go build -o ./bin/vanity-wallet-linux-amd64
```

For linux:
```
```
