# go-spf
[![CI](https://github.com/apprentice-system/go-spf/actions/workflows/go-test.yml/badge.svg?branch=main)](https://github.com/apprentice-systems/go-spf/actions/workflows/go-test.yml)
RFC Compliant Go library for parsing, analyzing, and evaluating SPF records
> Early proof of concept. The public API compiles and returns Neutral for every input. The real decision tree is in progress. Use at your own risk.


## Installation
```shell
# Until a real tag is published you must point at main
 go get github.com/apprentice-systems/go-spf@main
```


## Quick Start
```go
package main

import (
    "fmt"
    "net"

    "github.com/apprentice-systems/go-spf"
)

func main() {
    ip := net.ParseIP("192.0.2.1")
    res, err := spf.CheckHost(ip, "example.com", "alice@example.com")
    if err != nil {
        panic(err)
    }
    fmt.Println(res) // Neutral for now
}
```

