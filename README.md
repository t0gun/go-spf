# spf
[![CI](https://github.com/mailspire/spf/actions/workflows/go-test.yaml/badge.svg?branch=main)](https://github.com/mailspire/spf/actions/workflows/go-test.yaml)    [![Go Reference](https://pkg.go.dev/badge/github.com/mailspire/spf.svg)](https://pkg.go.dev/github.com/mailspire/spf)



RFC Compliant Go library for parsing, analyzing, and evaluating SPF records
>  [!WARNING]
> Early proof of concept. The public API compiles and returns Neutral for every input. The real decision tree is in progress.


## Installation
```shell
 go get github.com/mailspire/spf
```


## Quick Start
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
    fmt.Println(res.Code) // Neutral for now
}
```


## Contributing
Please feel free to submit issues, fork the repository and send pull requests!


## License
This project is licensed under the terms of the MIT license.
