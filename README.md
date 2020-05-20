# domain
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go ReportCard](https://goreportcard.com/badge/github.com/lynxsecurity/domain)](https://goreportcard.com/report/github.com/lynxsecurity/domain)
[![GoDoc]](https://godoc.org/github.com/lynxxsecurity/domain?status.svg)(https://godoc.org/github.com/lynxxsecurity/domain)
domain is a simple domain name parser for golang. 

## usage:

```golang
d, err := domains.New("/tmp/tld.cache")
if err != nil {
	log.Fatal(err)
}
record := d.Parse("www.hackerone.com")
// record.Subdomain = "www"
// record.Name = "hackerone"
// record.TLD = "com"
levels := d.Levels("super.long.subdomain.for.example.com")
// fmt.Println(levels)
// []string{"super.long.subdomain.for.example.com", "long.subdomain.for.example.com", "subdomain.for.example.com", "for.example.com", "example.com"}
```

## credits:
Inspired by [tldomains](https://github.com/jakewarren/tldomains)
