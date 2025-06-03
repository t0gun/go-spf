# spf
[![CI](https://github.com/apprentice-system/go-spf/actions/workflows/go-test.yaml/badge.svg?branch=main)](https://github.com/apprentice-system/go-spf/actions/workflows/go-test.yaml)  


RFC Compliant Go library for parsing, analyzing, and evaluating SPF records
>  [!WARNING]
> Early proof of concept. The public API compiles and returns Neutral for every input. The real decision tree is in progress.


## Installation
```shell
 go get go.apprentice.systems/spf
```


## Quick Start
```go
package main

import (
    "fmt"
    "net"

    "go.apprentice.systems/spf"
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
