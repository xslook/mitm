# mitm
A golang mitm library


### Request
To use this library, you should have a CA (cert.pem and key.pem).

If you don't have CA files, you can use *openssl* to generate a custom one like below.
```shell
# generate a local RSA CA
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem
```


### Usage
```go
package main

import (
    "github.com/xslook/mitm"
)

func main() {
    opts := mitm.Options{
        CA:     cert,
        Handle: mitmHandler,
    }
    proxy, err := mitm.New(opts)
    if err != nil {
        panic(err)
    }
    http.ListenAndServe(":8080", proxy)
}
```


### LICENSE
This project is licensed under the terms of the MIT license.

