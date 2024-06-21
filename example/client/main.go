package main

import (
	"fmt"
	"io"

	"github.com/RealImage/bifrost"
	"github.com/google/uuid"
)

var namespace = uuid.MustParse("01881c8c-e2e1-4950-9dee-3a9558c6c741")

func main() {
	key, err := bifrost.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	client, err := bifrost.HTTPClient("http://127.0.0.1:8008", namespace, key, nil, nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Get("https://127.0.0.1:8443")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.Status)
	fmt.Println(string(body))
}
