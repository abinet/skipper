package net

import (
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestRemoteHost(t *testing.T) {
	for _, tt := range []struct {
		name   string
		input  string
		want   net.IP
		fwdHdr string
	}{
		{"no header1", "127.0.0.1", net.IPv4(127, 0, 0, 1), ""},
		{"no header2", "1.2.3.4", net.IPv4(1, 2, 3, 4), ""},
		{"no header3", "100.200.300.400", nil, ""},
		{"no header4", "127.0.0.1:8080", net.IPv4(127, 0, 0, 1), ""},
		{"single header1", "127.0.0.1", net.IPv4(172, 16, 0, 1), "172.16.0.1"},
		{"invalid header", "127.0.0.1", net.IPv4(127, 0, 0, 1), "invalid header"},
		{"multiple header1", "127.0.0.1", net.IPv4(172, 16, 0, 1), "172.16.0.1, 1.2.3.4, 8.7.6.5"}, // X-Forwarded-For with proxies in it
		{"no header5", "2001:4860:0:2001::68", net.ParseIP("2001:4860:0:2001::68"), ""},
		{"single header2", "127.0.0.1", net.ParseIP("2001:4860:0:2001::68"), "2001:4860:0:2001::68"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.input, Header: make(http.Header)}
			if tt.fwdHdr != "" {
				r.Header.Set("x-forwarded-for", tt.fwdHdr)
			}
			got := RemoteHost(r)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Unexpected IP address '%v'. Wanted '%v", got, tt.want)
			}
		})
	}
}

func BenchmarkRemoteHost(b *testing.B) {
	r := &http.Request{RemoteAddr: "1.2.3.4"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RemoteHost(r)
	}
}

func TestRemoteHostFromLast(t *testing.T) {
	for _, tt := range []struct {
		name   string
		input  string
		want   net.IP
		fwdHdr []string
	}{
		{"no header", "127.0.0.1", net.IPv4(127, 0, 0, 1), []string{}},
		{"no header2", "1.2.3.4", net.IPv4(1, 2, 3, 4), []string{}},
		{"no header3", "100.200.300.400", nil, []string{}},
		{"no header4", "127.0.0.1:8080", net.IPv4(127, 0, 0, 1), []string{}},
		{"single header", "127.0.0.1", net.IPv4(172, 16, 0, 1), []string{"172.16.0.1"}},
		{"invalid  header", "127.0.0.1", net.IPv4(127, 0, 0, 1), []string{"invalid header"}},
		{"multiple entries", "127.0.0.1", net.IPv4(8, 7, 6, 5), []string{"172.16.0.1", "1.2.3.4", "8.7.6.5"}},
		{"2 entries", "127.0.0.1", net.IPv4(8, 7, 6, 5), []string{"1.2.3.4", "8.7.6.5"}},
		{"single header2", "127.0.0.1", net.IPv4(8, 7, 6, 5), []string{"8.7.6.5"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tt.input, Header: make(http.Header)}
			s := strings.Join(tt.fwdHdr, ", ")
			r.Header.Set("x-forwarded-for", s)
			got := RemoteHostFromLast(r)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Unexpected IP address '%v'. Wanted '%v", got, tt.want)
			}
		})
	}
}

func BenchmarkRemoteHostFromLast(b *testing.B) {
	r := &http.Request{RemoteAddr: "1.2.3.4"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RemoteHostFromLast(r)
	}
}

func TestIPNetsParse(t *testing.T) {
	for _, tt := range []struct {
		input []string
	}{
		{[]string{"1.2.3.4/"}},
		{[]string{"1.2.3.4/245"}},
		{[]string{"whatever"}},
		{[]string{"1.2.3.4/24", "whatever"}},
	} {
		t.Run(strings.Join(tt.input, ","), func(t *testing.T) {
			_, err := ParseCIDRs(tt.input)
			t.Logf("ParseCIDRs: %v", err)
			if err == nil {
				t.Errorf("parse error expected")
			}
		})
	}
}

func TestIPNetsContain(t *testing.T) {
	for _, tt := range []struct {
		input []string
		ip    net.IP
	}{
		{[]string{"1.2.3.4/24"}, net.IPv4(1, 2, 3, 4)},
		{[]string{"1.2.3.4/24", "5.6.7.8"}, net.IPv4(5, 6, 7, 8)},
		{[]string{"1.2.3.4/24", "5.6.7.8", "2001:db8::/32"}, net.ParseIP("2001:db8::aa")},
	} {
		t.Run(strings.Join(tt.input, ","), func(t *testing.T) {
			nets, err := ParseCIDRs(tt.input)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !nets.Contain(tt.ip) {
				t.Errorf("nets %v expected to contain %v", nets, tt.ip)
			}
		})
	}
}

func TestIPNetsDoNotContain(t *testing.T) {
	for _, tt := range []struct {
		input []string
		ip    net.IP
	}{
		{[]string{}, net.IPv4(4, 3, 2, 1)},
		{[]string{"1.2.3.4/24"}, net.IPv4(4, 3, 2, 1)},
		{[]string{"1.2.3.4/24", "5.6.7.8"}, net.IPv4(4, 3, 2, 1)},
		{[]string{"1.2.3.4/24", "5.6.7.8", "2001:db8::/32"}, net.IPv4(4, 3, 2, 1)},
	} {
		t.Run(strings.Join(tt.input, ","), func(t *testing.T) {
			nets, err := ParseCIDRs(tt.input)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if nets.Contain(tt.ip) {
				t.Errorf("nets %v expected to contain %v", nets, tt.ip)
			}
		})
	}
}
