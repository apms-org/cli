package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/html"
)

const (
	iconMaxHosts       = 300
	iconHTMLLimit      = 512 << 10
	iconBodyLimit      = 256 << 10
	iconHostTimeout    = 6 * time.Second
	iconMaxRedirects   = 3
	iconMaxConcurrent  = 4
	iconNegativeTTL    = 3 * 24 * time.Hour
	iconRefreshAfter   = 30 * 24 * time.Hour
	iconMaxEntries     = 2000
	iconNotifyInterval = 500 * time.Millisecond
	iconMaxCandidates  = 4
)

var iconAcceptedTypes = map[string]bool{
	"image/png":                true,
	"image/x-icon":             true,
	"image/vnd.microsoft.icon": true,
	"image/jpeg":               true,
	"image/webp":               true,
	"image/gif":                true,
	"image/svg+xml":            true,
}

type iconMeta struct {
	Host      string    `json:"host"`
	Type      string    `json:"type"`
	FetchedAt time.Time `json:"fetchedAt"`
	OK        bool      `json:"ok"`
}

type iconService struct {
	mu       sync.Mutex
	dir      string
	client   *http.Client
	sem      chan struct{}
	inflight map[string]bool
	notify   func(hosts []string)
	batch    []string
	timer    *time.Timer
	wg       sync.WaitGroup
}

func iconCacheDir() string {
	file := bridgeTokenFile()
	if file == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(file), "icons")
}

func newIconService(dir string, client *http.Client, notify func(hosts []string)) *iconService {
	if client == nil {
		client = newIconHTTPClient(nil)
	}
	return &iconService{dir: dir, client: client, sem: make(chan struct{}, iconMaxConcurrent), inflight: map[string]bool{}, notify: notify}
}

func iconsOffline() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("APM_ICONS_OFFLINE")))
	return v != "" && v != "0" && v != "false" && v != "off"
}

func iconKey(raw string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "www.")
	if !iconHostAllowed(h) {
		return "", false
	}
	return h, true
}

func iconHostAllowed(h string) bool {
	if h == "" || !strings.Contains(h, ".") || net.ParseIP(h) != nil {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".internal") {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r > 127) {
			return false
		}
	}
	return true
}

var iconCGNAT = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func iconIPBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || iconCGNAT.Contains(ip)
}

func iconDialControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if iconIPBlocked(net.ParseIP(host)) {
		return fmt.Errorf("icon fetch refused for address %s", host)
	}
	return nil
}

type iconGuardTransport struct {
	base http.RoundTripper
}

func (t iconGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, errors.New("icon fetches use https only")
	}
	if !iconHostAllowed(strings.ToLower(req.URL.Hostname())) {
		return nil, errors.New("icon fetch refused for this host")
	}
	return t.base.RoundTrip(req)
}

func newIconHTTPClient(base http.RoundTripper) *http.Client {
	if base == nil {
		dialer := &net.Dialer{Timeout: iconHostTimeout, Control: iconDialControl}
		base = &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   iconHostTimeout,
			ResponseHeaderTimeout: iconHostTimeout,
			MaxIdleConns:          8,
			IdleConnTimeout:       30 * time.Second,
		}
	}
	return &http.Client{
		Transport: iconGuardTransport{base: base},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > iconMaxRedirects {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("redirect left https")
			}
			return nil
		},
	}
}

func (ic *iconService) paths(key string) (string, string) {
	sum := sha256.Sum256([]byte(key))
	name := hex.EncodeToString(sum[:])
	return filepath.Join(ic.dir, name+".img"), filepath.Join(ic.dir, name+".json")
}

func (ic *iconService) readMeta(key string) (iconMeta, bool) {
	if ic.dir == "" {
		return iconMeta{}, false
	}
	_, metaPath := ic.paths(key)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return iconMeta{}, false
	}
	var m iconMeta
	if json.Unmarshal(data, &m) != nil || m.Host != key {
		return iconMeta{}, false
	}
	return m, true
}

func (ic *iconService) readDataURI(key string) (string, bool) {
	imgPath, _ := ic.paths(key)
	data, err := os.ReadFile(imgPath)
	if err != nil || len(data) == 0 || len(data) > iconBodyLimit {
		return "", false
	}
	typ := sniffIconType(data)
	if typ == "" {
		return "", false
	}
	return "data:" + typ + ";base64," + base64.StdEncoding.EncodeToString(data), true
}

func writeFileAtomic(dir, path string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func (ic *iconService) store(key, typ string, data []byte, ok bool) error {
	if ic.dir == "" {
		return errors.New("no icon cache directory")
	}
	if err := os.MkdirAll(ic.dir, 0700); err != nil {
		return err
	}
	imgPath, metaPath := ic.paths(key)
	if ok {
		if err := writeFileAtomic(ic.dir, imgPath, data); err != nil {
			return err
		}
	} else {
		_ = os.Remove(imgPath)
	}
	meta, _ := json.Marshal(iconMeta{Host: key, Type: typ, FetchedAt: time.Now().UTC(), OK: ok})
	if err := writeFileAtomic(ic.dir, metaPath, meta); err != nil {
		return err
	}
	ic.prune()
	return nil
}

func (ic *iconService) touch(key string, m iconMeta) {
	_, metaPath := ic.paths(key)
	m.FetchedAt = time.Now().UTC()
	if meta, err := json.Marshal(m); err == nil {
		_ = writeFileAtomic(ic.dir, metaPath, meta)
	}
}

func (ic *iconService) prune() {
	entries, err := os.ReadDir(ic.dir)
	if err != nil {
		return
	}
	type aged struct {
		base string
		at   time.Time
	}
	list := []aged{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		list = append(list, aged{base: strings.TrimSuffix(name, ".json"), at: info.ModTime()})
	}
	if len(list) <= iconMaxEntries {
		return
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	for _, a := range list[:len(list)-iconMaxEntries] {
		_ = os.Remove(filepath.Join(ic.dir, a.base+".json"))
		_ = os.Remove(filepath.Join(ic.dir, a.base+".img"))
	}
}

func (ic *iconService) clear() error {
	if ic.dir == "" {
		return nil
	}
	return os.RemoveAll(ic.dir)
}

func (ic *iconService) lookup(hosts []string, allowFetch bool) (map[string]any, []string) {
	icons := map[string]any{}
	pending := []string{}
	for _, raw := range hosts {
		if _, seen := icons[raw]; seen {
			continue
		}
		icons[raw] = nil
		key, ok := iconKey(raw)
		if !ok {
			continue
		}
		m, has := ic.readMeta(key)
		now := time.Now()
		if has && m.OK {
			if uri, ok := ic.readDataURI(key); ok {
				icons[raw] = uri
				if allowFetch && now.Sub(m.FetchedAt) > iconRefreshAfter {
					ic.start(key, true)
				}
				continue
			}
			has = false
		}
		if has && !m.OK && now.Sub(m.FetchedAt) < iconNegativeTTL {
			continue
		}
		if allowFetch && ic.start(key, false) {
			pending = append(pending, raw)
		}
	}
	return icons, pending
}

func (ic *iconService) start(key string, refresh bool) bool {
	ic.mu.Lock()
	if ic.inflight[key] {
		ic.mu.Unlock()
		return true
	}
	ic.inflight[key] = true
	ic.wg.Add(1)
	ic.mu.Unlock()
	go func() {
		defer ic.wg.Done()
		ic.sem <- struct{}{}
		typ, data, err := ic.fetch(key)
		<-ic.sem
		switch {
		case err == nil:
			_ = ic.store(key, typ, data, true)
		case refresh:
			if m, ok := ic.readMeta(key); ok {
				ic.touch(key, m)
			}
		default:
			_ = ic.store(key, "", nil, false)
		}
		ic.mu.Lock()
		delete(ic.inflight, key)
		ic.mu.Unlock()
		ic.queueNotify(key)
	}()
	return true
}

func (ic *iconService) queueNotify(key string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	ic.batch = append(ic.batch, key)
	if ic.timer != nil {
		return
	}
	ic.timer = time.AfterFunc(iconNotifyInterval, func() {
		ic.mu.Lock()
		hosts := ic.batch
		ic.batch = nil
		ic.timer = nil
		ic.mu.Unlock()
		if len(hosts) > 0 && ic.notify != nil {
			sort.Strings(hosts)
			ic.notify(hosts)
		}
	})
}

func sniffIconType(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch ct := http.DetectContentType(b); ct {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/x-icon", "image/vnd.microsoft.icon":
		return ct
	}
	head := b
	if len(head) > 4096 {
		head = head[:4096]
	}
	head = bytes.TrimPrefix(head, []byte{0xef, 0xbb, 0xbf})
	low := strings.ToLower(strings.TrimSpace(string(head)))
	if strings.HasPrefix(low, "<svg") {
		return "image/svg+xml"
	}
	if (strings.HasPrefix(low, "<?xml") || strings.HasPrefix(low, "<!--") || strings.HasPrefix(low, "<!doctype svg")) && strings.Contains(low, "<svg") && !strings.Contains(low, "<html") {
		return "image/svg+xml"
	}
	return ""
}

type iconCandidate struct {
	href string
	rank int
	size int
}

func iconLinkCandidates(page []byte, base *url.URL) []iconCandidate {
	z := html.NewTokenizer(bytes.NewReader(page))
	out := []iconCandidate{}
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if string(name) != "link" || !hasAttr {
			continue
		}
		var rel, href, sizes, typ string
		for {
			k, v, more := z.TagAttr()
			switch string(k) {
			case "rel":
				rel = strings.ToLower(string(v))
			case "href":
				href = strings.TrimSpace(string(v))
			case "sizes":
				sizes = strings.ToLower(string(v))
			case "type":
				typ = strings.ToLower(string(v))
			}
			if !more {
				break
			}
		}
		if href == "" {
			continue
		}
		tokens := map[string]bool{}
		for _, t := range strings.Fields(rel) {
			tokens[t] = true
		}
		size := 0
		for _, s := range strings.Fields(sizes) {
			if s == "any" {
				size = 1 << 20
				continue
			}
			if parts := strings.SplitN(s, "x", 2); len(parts) == 2 {
				if n, err := strconv.Atoi(parts[0]); err == nil && n > size {
					size = n
				}
			}
		}
		lowHref := strings.ToLower(href)
		svg := typ == "image/svg+xml" || strings.HasSuffix(strings.SplitN(lowHref, "?", 2)[0], ".svg") || strings.HasPrefix(lowHref, "data:image/svg+xml")
		png := typ == "image/png" || strings.HasSuffix(strings.SplitN(lowHref, "?", 2)[0], ".png") || strings.HasPrefix(lowHref, "data:image/png")
		rank := -1
		switch {
		case tokens["apple-touch-icon"] || tokens["apple-touch-icon-precomposed"]:
			rank = 0
		case tokens["icon"] && png:
			rank = 1
		case tokens["icon"] && svg:
			rank = 2
		case tokens["icon"]:
			rank = 3
		case tokens["mask-icon"]:
			rank = 4
		}
		if rank < 0 {
			continue
		}
		if !strings.HasPrefix(lowHref, "data:") {
			u, err := base.Parse(href)
			if err != nil {
				continue
			}
			href = u.String()
		}
		out = append(out, iconCandidate{href: href, rank: rank, size: size})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank < out[j].rank
		}
		return out[i].size > out[j].size
	})
	return out
}

func decodeIconDataURI(s string) ([]byte, error) {
	rest := strings.TrimPrefix(s, "data:")
	i := strings.Index(rest, ",")
	if i < 0 {
		return nil, errors.New("bad data uri")
	}
	meta, payload := rest[:i], rest[i+1:]
	if strings.HasSuffix(strings.ToLower(meta), ";base64") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(payload), "="))
		}
		return b, err
	}
	un, err := url.PathUnescape(payload)
	return []byte(un), err
}

func (ic *iconService) get(ctx context.Context, target string, limit int64) ([]byte, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "APM/"+Version+" (+icon)")
	req.Header.Set("Accept", "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,text/html;q=0.5,*/*;q=0.1")
	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, errors.New("response too large")
	}
	return data, resp.Request.URL, nil
}

func (ic *iconService) fetchImage(ctx context.Context, href string) (string, []byte, error) {
	var data []byte
	if strings.HasPrefix(strings.ToLower(href), "data:") {
		b, err := decodeIconDataURI(href)
		if err != nil {
			return "", nil, err
		}
		data = b
	} else {
		b, _, err := ic.get(ctx, href, iconBodyLimit)
		if err != nil {
			return "", nil, err
		}
		data = b
	}
	if len(data) == 0 || len(data) > iconBodyLimit {
		return "", nil, errors.New("icon size out of range")
	}
	typ := sniffIconType(data)
	if !iconAcceptedTypes[typ] {
		return "", nil, errors.New("not an icon")
	}
	return typ, data, nil
}

func (ic *iconService) fetch(key string) (string, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), iconHostTimeout)
	defer cancel()
	root := "https://" + key + "/"
	if page, final, err := ic.get(ctx, root, iconHTMLLimit); err == nil {
		for i, c := range iconLinkCandidates(page, final) {
			if i >= iconMaxCandidates {
				break
			}
			if typ, data, err := ic.fetchImage(ctx, c.href); err == nil {
				return typ, data, nil
			}
		}
	}
	return ic.fetchImage(ctx, root+"favicon.ico")
}

func (s *desktopServer) iconFetchAllowed() bool {
	if iconsOffline() || !s.unlocked() {
		return false
	}
	if d := s.vault.Desktop; d != nil {
		switch v := d.Settings["siteIcons"].(type) {
		case bool:
			return v
		case string:
			return !strings.EqualFold(strings.TrimSpace(v), "off")
		}
	}
	return true
}

func (s *desktopServer) iconLookup(p json.RawMessage) (map[string]any, error) {
	var in struct {
		Hosts []string `json:"hosts"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if len(in.Hosts) > iconMaxHosts {
		return nil, rpcErr("invalid", fmt.Sprintf("Ask for at most %d hosts at a time.", iconMaxHosts))
	}
	icons, pending := s.icons.lookup(in.Hosts, s.iconFetchAllowed())
	return map[string]any{"icons": icons, "pending": pending}, nil
}

func hIconsGet(s *desktopServer, p json.RawMessage) (any, error) {
	return s.iconLookup(p)
}

func hIconsClear(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.icons.clear(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func bridgeIcons(b *desktopBridge, c *bridgeCtx) (map[string]any, error) {
	return b.s.iconLookup(c.body)
}
