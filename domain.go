// Copyright 2020 Lynx Security LLC. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file

/*
Package domain is a simple domain name parsing library for golang.

The following shows an example usage of the library:
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


*/
package domain

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Domain is the core structure, a domain name parser
type Domain struct {
	tlds  *tldMap
	Cache string
}

// Record holds a parsed domain name
type Record struct {
	Subdomain, Name, TLD string
}

// String() converts a record to a string
func (r *Record) String() string {
	return strings.ToLower(fmt.Sprintf("%s.%s.%s", r.Subdomain, r.Name, r.TLD))
}

// New creates and returns a new domain object
func New(cacheFile string) (*Domain, error) {
	if !cacheExists(cacheFile) {
		err := newCache(cacheFile)
		if err != nil {
			return nil, err
		}
	}

	cache, err := os.Open(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("Could not open cache file: %v", err)
	}
	defer cache.Close()
	tlds := &tldMap{m: make(map[string]struct{})}
	b := bufio.NewScanner(cache)
	for b.Scan() {
		tlds.add(b.Text())
	}
	d := &Domain{
		Cache: cacheFile,
		tlds:  tlds,
	}
	return d, nil
}

// Parse parses a domain and extracts it into a Record object
func (d *Domain) Parse(domain string) (*Record, error) {
	var rec Record
	var err error
	domain = strings.ToLower(domain)
	err = validator(domain)
	if err != nil {
		return nil, err
	}
	chunks := strings.Split(domain, ".")
	cl := len(chunks)

	var tld string
	for i := cl - 1; i >= 0; i-- {
		c := chunks[i]
		if tld == "" {
			tld = c
		} else {
			tld = c + "." + tld
		}
		if ok := d.tlds.exists(tld); ok {
			rec.TLD = tld
		} else if rec.Name == "" {
			rec.Name = c
		} else {
			if rec.Subdomain == "" {
				rec.Subdomain = c
			} else {
				rec.Subdomain = c + "." + rec.Subdomain
			}
		}
	}
	if rec.TLD == "" {
		return nil, fmt.Errorf("parse: \"%s\": top level domain doe not exist", domain)
	}
	if rec.Name == "" {
		return nil, fmt.Errorf("parse: \"%s\": missing domain name", domain)
	}
	return &rec, nil
}

// Levels returns all subdomain levels for a given record
func (d *Domain) Levels(DomainName string) []string {
	DomainName = strings.ToLower(DomainName)
	var levels []string
	h, err := d.Parse(DomainName)
	if err != nil {
		return []string{}
	}
	t := len(DomainName) - len(h.TLD)
	all := strings.Split(DomainName[:t], ".")
	for i := 0; i <= len(all)-2; i++ {
		sub := strings.Join(all[i:], ".")
		sub += h.TLD
		levels = append(levels, sub)
	}
	return levels
}

// newCache downloads the TLD suffix list and creates a new cache file
func newCache(cacheFile string) error {
	cache, err := os.OpenFile(cacheFile, os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("Could not create new cache file: %v", err)
	}
	defer cache.Close()
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://publicsuffix.org/list/public_suffix_list.dat")
	if err != nil {
		return fmt.Errorf("Could not download suffix list: %v", err)
	}
	defer resp.Body.Close()
	scan := bufio.NewScanner(resp.Body)
	for scan.Scan() {
		line := scan.Text()
		if line != "" && !strings.HasPrefix(line, "/") {
			cache.WriteString(line)
			cache.WriteString("\n")
		}
	}
	return nil
}

// cacheExists checks if a file exists
func cacheExists(cacheFile string) bool {
	if _, err := os.Stat(cacheFile); err == nil {
		return true
	} else if os.IsNotExist(err) {
		return false
	}
	return false
}

// tldMap is a thread safe map structure
type tldMap struct {
	sync.RWMutex
	m map[string]struct{}
}

// exists checks if a tld exists
func (t *tldMap) exists(tld string) bool {
	t.RLock()
	defer t.RUnlock()
	_, ok := t.m[tld]
	return ok
}

// add adds a tld to the map
func (t *tldMap) add(tld string) {
	t.Lock()
	defer t.Unlock()
	t.m[tld] = struct{}{}
}

// validator performs some simple checks on a string
func validator(domain string) error {
	var badchars = []rune{' ', '}', '{', '\'', '\\', '/', '"', ';', ':', '@', '!', '#', '$', '%', '^', '&', '(', ')'}
	for _, char := range badchars {
		if strings.ContainsRune(domain, char) {
			return fmt.Errorf("parse \"%s\": domain name cannot contain \"%c\"", domain, char)
		}
	}
	if !strings.ContainsRune(domain, '.') {
		return fmt.Errorf("parse \"%s\": domain name must contain at least one \".\"", domain)
	}
	if strings.Contains(domain, "..") {
		return fmt.Errorf("parse \"%s\": domain name cannot contain two consecutive \"..\"", domain)

	}
	return nil
}
