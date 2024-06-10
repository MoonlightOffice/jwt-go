# jwt-go
Simple JWT encoder & decoder


## Install
```shell
go get github.com/moonlightoffice/jwt-go@v0.1.0
```

## Usage
```go
package main

import (
	"fmt"

	"github.com/moonlightoffice/jwt-go"
)

func main() {
	// Encode
	token, _ := jwt.Encode(
		jwt.JoseHeader{Alg: jwt.AlgHS512},
		[]byte("Put your payload here!"),
		[]byte("SampleSecret"),
	)

	fmt.Println(token)

	// Decode

	payload, err := jwt.Decode(
		token,
		[]byte("SampleSecret"),
	)
	if err != nil {
		log.Fatal("invalid jwt secret or signature")
	}

	fmt.Println(string(payload))
}
```
