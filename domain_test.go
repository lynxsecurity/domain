package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecordString(t *testing.T) {
	tests := []struct {
		i Record
		o string
	}{
		{i: Record{"www", "example", "com"}, o: "www.example.com"},
		{i: Record{"EXAMPLEDOMAIN", "GOOGLE", "Co.Uk"}, o: "exampledomain.google.co.uk"},
		{i: Record{"long.subdomain.for", "example", "us.com"}, o: "long.subdomain.for.example.us.com"},
	}
	for _, ts := range tests {
		r := ts.i.String()
		assert.Equal(t, ts.o, r, "These should be equal!")
	}

}
func TestDomainParser(t *testing.T) {
	// define tests
	tests := []struct {
		i string
		o *Record
	}{
		{i: "WwW.eXample.com", o: &Record{"www", "example", "com"}},
		{i: "bad", o: nil},
		{i: " .com", o: nil},
		{i: "a..com", o: nil},
		{i: "..a.a.a.a", o: nil},
		{i: "thistlddoes.nonexist", o: nil},
		{i: "www.super.long.subdomain.hacking.us.com", o: &Record{"www.super.long.subdomain", "hacking", "us.com"}},
		{i: "blog.google", o: &Record{"", "blog", "google"}},
	}

	ex, _ := New("/tmp/tld.cache")
	for _, ts := range tests {
		r, _ := ex.Parse(ts.i)
		assert.Equal(t, ts.o, r, "These should be equal!")
	}
}

func TestDomainLevels(t *testing.T) {
	tests := []struct {
		i string
		o []string
	}{
		{i: "WwW.eXample.com", o: []string{"www.example.com", "example.com"}},
		{i: "super.long.subdomain.hacking.us.com", o: []string{"super.long.subdomain.hacking.us.com", "long.subdomain.hacking.us.com", "subdomain.hacking.us.com", "hacking.us.com"}},
		{i: "super.long.subdomain.for.example.com", o: []string{"super.long.subdomain.for.example.com", "long.subdomain.for.example.com", "subdomain.for.example.com", "for.example.com", "example.com"}},
		{i: "naan.example", o: []string{}},
	}
	ex, _ := New("/tmp/tld.cache")
	for _, ts := range tests {
		r := ex.Levels(ts.i)
		assert.Equal(t, ts.o, r, "These should be equal!")
	}

}
