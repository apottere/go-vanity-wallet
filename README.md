# Golang Vanity Wallet

## Features
* Configurable entropy from 128-256 bits
* Configurable derivation path (ETH/Metamask default: `m/44'/60'/0'/0`)

## Development

```
go run main.go 256 "m/44'/60'/0'/0"
```

## Build

```
go build -o ./bin/vanity-wallet
```