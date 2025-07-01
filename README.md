# spf
[![CI](https://github.com/mailspire/spf/actions/workflows/go-test.yaml/badge.svg?branch=main)](https://github.com/mailspire/spf/actions/workflows/go-test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mailspire/spf.svg)](https://pkg.go.dev/github.com/mailspire/spf)

RFC 7208 compliant Go library for parsing and evaluating SPF records.

> **Warning**
> This project is an early proof of concept. The evaluation logic is
> incomplete and currently returns `Neutral` for all inputs.

## Installation
```shell
go get github.com/mailspire/spf
```

## Usage

### Checking a host
```go
package main

import (
    "fmt"
    "net"

    "github.com/mailspire/spf"
)

func main() {
    ip := net.ParseIP("192.0.2.1")
    res, err := spf.CheckHost(ip, "example.com", "alice@example.com")
    if err != nil {
        panic(err)
    }
    fmt.Println(res.Code)
}
```

### Parsing a record
```go
rec, err := spf.Parse("v=spf1 ip4:203.0.113.0/24 -all")
if err != nil {
    // handle parse error
}
fmt.Printf("%+v\n", rec)
```

## Contributing
Please feel free to submit issues, fork the repository and send pull requests!

## License
This project is licensed under the terms of the MIT license.
