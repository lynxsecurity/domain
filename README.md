# domain
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/lynxsecurity/domain?)](https://goreportcard.com/report/github.com/lynxsecurity/domain)
[![GoDoc](https://godoc.org/github.com/lynxsecurity/domain?status.svg)](https://godoc.org/github.com/lynxsecurity/domain)

domain is a simple domain name parser for golang. 

## usage:

```golang
package main

import (
	"fmt"
	"log"

	"github.com/lynxsecurity/domain"
)

func main() {
	d, err := domain.New("/tmp/tld.cache")
	if err != nil {
		log.Fatal(err)
	}
	record, err := d.Parse("www.hackerone.com")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Subdomain:", record.Subdomain)
	fmt.Println("Name: ", record.Name)
	fmt.Println("TLD:", record.TLD)
	fmt.Println()
	levels := d.Levels("long.subdomain.for.example.com")
	fmt.Println("Levels")
	for _, level := range levels {
		fmt.Println("-", level)
	}
}
```

## credits:
Inspired by [tldomains](https://github.com/jakewarren/tldomains)
