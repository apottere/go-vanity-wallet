# Golang Vanity Wallet

## Features
* Configurable entropy from 128-256 bits
* Configurable derivation path (ETH/Metamask default: `m/44'/60'/0'/0`)

## Development

```
go run main.go 1 256 "m/44'/60'/0'/0/0"
```

## Build

```
go build -o ./bin/vanity-wallet
```

For linux:
```
GOOS=linux GOARCH=amd64 go build -o ./bin/vanity-wallet-linux-amd64
```
