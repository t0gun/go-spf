# go-spf
[![CI](https://github.com/t0gun/go-spf/actions/workflows/go-test.yaml/badge.svg?branch=main)](https://github.com/t0gun/go-spf/actions/workflows/go-test.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/t0gun/go-spf.svg)](https://pkg.go.dev/github.com/t0gun/go-spf)

RFC 7208 compliant Go library for parsing and evaluating SPF records.
> Requires go 1.23.x or later

> **Warning**
> This project is an early proof of concept. The evaluation logic is
> incomplete and currently returns `Neutral` for all inputs.

## Installation
```shell
go get github.com/t0gun/go-spf
```

## Usage

### Checking a host
```go
package main

import (
    "fmt"
    "net"

    "github.com/t0gun/go-spf"
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
The parser lives in its own subpackage and can be used directly if you only
need to read an SPF record.
```go
import "github.com/t0gun/go-spf/parser"

rec, err := parser.Parse("v=spf1 ip4:203.0.113.0/24 -all")
if err != nil {
    // handle parse error
}
fmt.Printf("%+v\n", rec)
```

## Contributing
Please feel free to submit issues, fork the repository and send pull requests!

## License
This project is licensed under the terms of the MIT license.
