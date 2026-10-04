package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testPNG = append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), bytes.Repeat([]byte{7}, 40)...)

var testICO = append([]byte{0, 0, 1, 0, 1, 0, 16, 16}, bytes.Repeat([]byte{3}, 40)...)

const testSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>`

type iconSite struct {
	mu    sync.Mutex
	hits  map[string]int
	delay time.Duration
}

func (s *iconSite) count(host, path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[host+path]
}

func (s *iconSite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.Split(r.Host, ":")[0]
	s.mu.Lock()
	s.hits[host+r.URL.Path]++
	delay := s.delay
	s.mu.Unlock()
	if !strings.HasPrefix(r.UserAgent(), "APM/") || !strings.HasSuffix(r.UserAgent(), "(+icon)") {
		http.Error(w, "bad agent", 400)
		return
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	page := func(body string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head>"+body+"</head><body>hi</body></html>")
	}
	switch host + r.URL.Path {
	case "good.example/":
		page(`<link rel="icon" href="/small.png" sizes="16x16"><link rel="stylesheet" href="/x.css"><LINK REL="apple-touch-icon" HREF="/apple.png">`)
	case "good.example/apple.png":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(testPNG)
	case "good.example/small.png":
		_, _ = w.Write(testICO)
	case "sizes.example/":
		page(`<link rel="icon" href="/a.png" sizes="16x16"><link rel="icon" href="/b.png" sizes="192x192"><link rel="mask-icon" href="/mask.svg">`)
	case "sizes.example/b.png":
		_, _ = w.Write(testPNG)
	case "svg.example/":
		page(`<link rel="mask-icon" href="/mask.svg"><link rel="icon" type="image/svg+xml" href="img/icon.svg">`)
	case "svg.example/img/icon.svg":
		w.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(w, testSVG)
	case "data.example/":
		page(`<link rel="shortcut icon" href="data:image/png;base64,` + base64.StdEncoding.EncodeToString(testPNG) + `">`)
	case "fallback.example/favicon.ico":
		_, _ = w.Write(testICO)
	case "redirect.example/favicon.ico":
		http.Redirect(w, r, "https://redirect.example/r1", http.StatusFound)
	case "redirect.example/r1":
		http.Redirect(w, r, "/r2", http.StatusFound)
	case "redirect.example/r2":
		http.Redirect(w, r, "/r3", http.StatusFound)
	case "redirect.example/r3":
		_, _ = w.Write(testPNG)
	case "toomany.example/favicon.ico":
		http.Redirect(w, r, "/t1", http.StatusFound)
	case "toomany.example/t1":
		http.Redirect(w, r, "/t2", http.StatusFound)
	case "toomany.example/t2":
		http.Redirect(w, r, "/t3", http.StatusFound)
	case "toomany.example/t3":
		http.Redirect(w, r, "/t4", http.StatusFound)
	case "toomany.example/t4":
		_, _ = w.Write(testPNG)
	case "insecure.example/favicon.ico":
		http.Redirect(w, r, "http://insecure.example/plain.png", http.StatusFound)
	case "internal.example/favicon.ico":
		http.Redirect(w, r, "https://127.0.0.1/x.png", http.StatusFound)
	case "big.example/favicon.ico":
		_, _ = w.Write(append(append([]byte{}, testPNG...), make([]byte, iconBodyLimit)...))
	case "html.example/favicon.ico", "html.example/":
		page("")
	case "slow.example/favicon.ico":
		_, _ = w.Write(testPNG)
	default:
		http.NotFound(w, r)
	}
}

func newTestIconService(t *testing.T) (*iconService, *iconSite, chan []string) {
	t.Helper()
	site := &iconSite{hits: map[string]int{}}
	srv := httptest.NewTLSServer(site)
	t.Cleanup(srv.Close)
	base := srv.Client().Transport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	addr := srv.Listener.Addr().String()
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	updates := make(chan []string, 32)
	ic := newIconService(filepath.Join(t.TempDir(), "icons"), newIconHTTPClient(base), func(hosts []string) { updates <- hosts })
	return ic, site, updates
}

func waitIconUpdates(t *testing.T, ic *iconService, updates chan []string, want int) []string {
	t.Helper()
	ic.wg.Wait()
	got := []string{}
	deadline := time.After(5 * time.Second)
	for len(got) < want {
		select {
		case hosts := <-updates:
			got = append(got, hosts...)
		case <-deadline:
			t.Fatalf("icons.updated carried %v, want %d hosts", got, want)
		}
	}
	return got
}

func TestIconKey(t *testing.T) {
	ok := map[string]string{
		"github.com":                         "github.com",
		"https://www.GitHub.com:443/login?x": "github.com",
		"mail.google.com":                    "mail.google.com",
		"user@vercel.com":                    "vercel.com",
		"docs.example.co.uk.":                "docs.example.co.uk",
	}
	for in, want := range ok {
		if got, valid := iconKey(in); !valid || got != want {
			t.Errorf("iconKey(%q) = %q %v, want %q", in, got, valid, want)
		}
	}
	for _, in := range []string{"", "localhost", "app.localhost", "printer.local", "db.internal", "intranet", "10.0.0.1", "[::1]:8080", "8.8.8.8", "https://192.168.1.1/", "evil host.com", "a_b.example"} {
		if got, valid := iconKey(in); valid {
			t.Errorf("iconKey(%q) should be refused, got %q", in, got)
		}
	}
}

func TestIconSSRFGuard(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "100.64.0.1", "100.127.255.254", "224.0.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"} {
		if !iconIPBlocked(net.ParseIP(ip)) {
			t.Errorf("%s should be blocked", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "140.82.112.3", "100.128.0.1", "2606:4700::1111"} {
		if iconIPBlocked(net.ParseIP(ip)) {
			t.Errorf("%s should be allowed", ip)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	d := &net.Dialer{Timeout: time.Second, Control: iconDialControl}
	if conn, err := d.Dial("tcp", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatalf("the icon dialer connected to loopback")
	} else if !strings.Contains(err.Error(), "refused for address") {
		t.Fatalf("unexpected dial error: %v", err)
	}
	client := newIconHTTPClient(nil)
	for _, target := range []string{"http://github.com/", "https://127.0.0.1/", "https://localhost/", "https://printer.local/"} {
		if resp, err := client.Get(target); err == nil {
			resp.Body.Close()
			t.Fatalf("%s should be refused before any connection", target)
		}
	}
}

func TestIconFetchAndCache(t *testing.T) {
	ic, site, updates := newTestIconService(t)
	hosts := []string{"good.example", "sizes.example", "svg.example", "data.example", "fallback.example", "redirect.example", "toomany.example", "insecure.example", "internal.example", "big.example", "html.example", "localhost", "10.0.0.1"}
	icons, pending := ic.lookup(hosts, true)
	if len(pending) != 11 {
		t.Fatalf("pending = %v", pending)
	}
	for _, h := range hosts {
		if icons[h] != nil {
			t.Fatalf("%s should not be cached yet", h)
		}
	}
	updated := waitIconUpdates(t, ic, updates, 11)
	if strings.Join(updated, ",") == "" {
		t.Fatalf("no updates")
	}
	icons, pending = ic.lookup(hosts, true)
	if len(pending) != 0 {
		t.Fatalf("nothing should be pending after the fetch: %v", pending)
	}
	pngURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(testPNG)
	want := map[string]any{
		"good.example":     pngURI,
		"sizes.example":    pngURI,
		"svg.example":      "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(testSVG)),
		"data.example":     pngURI,
		"fallback.example": "data:image/x-icon;base64," + base64.StdEncoding.EncodeToString(testICO),
		"redirect.example": pngURI,
		"toomany.example":  nil,
		"insecure.example": nil,
		"internal.example": nil,
		"big.example":      nil,
		"html.example":     nil,
		"localhost":        nil,
		"10.0.0.1":         nil,
	}
	for h, w := range want {
		if icons[h] != w {
			t.Errorf("icon for %s = %.60v, want %.60v", h, icons[h], w)
		}
	}
	if site.count("good.example", "/small.png") != 0 || site.count("toomany.example", "/t4") != 0 || site.count("sizes.example", "/a.png") != 0 {
		t.Fatalf("fetched a lower ranked icon or followed a 4th redirect")
	}
	if n := site.count("html.example", "/"); n != 1 {
		t.Fatalf("html.example root fetched %d times", n)
	}
	ic.lookup([]string{"html.example"}, true)
	ic.wg.Wait()
	if n := site.count("html.example", "/"); n != 1 {
		t.Fatalf("a failure must be negatively cached, root fetched %d times", n)
	}

	entries, err := os.ReadDir(ic.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.Contains(name, "example") || !(strings.HasSuffix(name, ".img") || strings.HasSuffix(name, ".json")) || len(strings.Split(name, ".")[0]) != 64 {
			t.Fatalf("cache file name leaks or is malformed: %s", name)
		}
		if info, _ := e.Info(); info.Mode().Perm() != 0600 {
			t.Fatalf("cache file %s mode %v", name, info.Mode().Perm())
		}
	}
	m, ok := ic.readMeta("good.example")
	if !ok || !m.OK || m.Type != "image/png" || time.Since(m.FetchedAt) > time.Minute {
		t.Fatalf("sidecar = %+v", m)
	}
	if m, ok := ic.readMeta("html.example"); !ok || m.OK {
		t.Fatalf("negative sidecar = %+v", m)
	}

	if err := ic.clear(); err != nil {
		t.Fatal(err)
	}
	if icons, _ := ic.lookup([]string{"good.example"}, false); icons["good.example"] != nil {
		t.Fatalf("clear should empty the cache")
	}
	if _, err := os.Stat(ic.dir); !os.IsNotExist(err) {
		t.Fatalf("cache dir should be gone: %v", err)
	}
}

func TestIconSingleflightOfflineAndRefresh(t *testing.T) {
	ic, site, updates := newTestIconService(t)
	site.delay = 300 * time.Millisecond
	_, p1 := ic.lookup([]string{"slow.example"}, true)
	_, p2 := ic.lookup([]string{"slow.example", "slow.example"}, true)
	if len(p1) != 1 || len(p2) != 1 {
		t.Fatalf("pending = %v %v", p1, p2)
	}
	waitIconUpdates(t, ic, updates, 1)
	if n := site.count("slow.example", "/"); n != 1 {
		t.Fatalf("singleflight broken: root fetched %d times", n)
	}
	site.delay = 0

	icons, pending := ic.lookup([]string{"good.example"}, false)
	if icons["good.example"] != nil || len(pending) != 0 || site.count("good.example", "/") != 0 {
		t.Fatalf("fetch must not happen when disabled")
	}

	old := iconMeta{Host: "slow.example", Type: "image/png", FetchedAt: time.Now().Add(-31 * 24 * time.Hour), OK: true}
	data, _ := json.Marshal(old)
	_, metaPath := ic.paths("slow.example")
	if err := os.WriteFile(metaPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	icons, pending = ic.lookup([]string{"slow.example"}, true)
	if icons["slow.example"] == nil || len(pending) != 0 {
		t.Fatalf("a stale icon should be served while it refreshes: %v %v", icons, pending)
	}
	waitIconUpdates(t, ic, updates, 1)
	if n := site.count("slow.example", "/"); n != 2 {
		t.Fatalf("stale icon was not refreshed: %d", n)
	}
	if m, _ := ic.readMeta("slow.example"); time.Since(m.FetchedAt) > time.Minute {
		t.Fatalf("refresh did not update fetchedAt")
	}

	negative, _ := json.Marshal(iconMeta{Host: "good.example", FetchedAt: time.Now().Add(-4 * 24 * time.Hour)})
	_, goodMeta := ic.paths("good.example")
	if err := os.WriteFile(goodMeta, negative, 0600); err != nil {
		t.Fatal(err)
	}
	if _, pending := ic.lookup([]string{"good.example"}, true); len(pending) != 1 {
		t.Fatalf("an expired failure should be retried: %v", pending)
	}
	waitIconUpdates(t, ic, updates, 1)
}

func TestIconPruneAndParse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "icons")
	ic := newIconService(dir, nil, nil)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour)
	for i := 0; i < iconMaxEntries+3; i++ {
		key := fmt.Sprintf("h%d.example", i)
		img, meta := ic.paths(key)
		_ = os.WriteFile(img, testPNG, 0600)
		_ = os.WriteFile(meta, []byte(`{}`), 0600)
		at := start.Add(time.Duration(i) * time.Second)
		_ = os.Chtimes(meta, at, at)
	}
	ic.prune()
	for i := 0; i < 3; i++ {
		if _, meta := ic.paths(fmt.Sprintf("h%d.example", i)); fileExists(meta) {
			t.Fatalf("oldest entry %d was not pruned", i)
		}
	}
	if _, meta := ic.paths("h3.example"); !fileExists(meta) {
		t.Fatalf("pruned too much")
	}

	if sniffIconType([]byte("<!DOCTYPE html><html><svg></svg></html>")) != "" || sniffIconType([]byte(testSVG)) != "image/svg+xml" || sniffIconType([]byte("<?xml version=\"1.0\"?>\n"+testSVG)) != "image/svg+xml" || sniffIconType(testICO) != "image/x-icon" {
		t.Fatalf("sniffing wrong")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
