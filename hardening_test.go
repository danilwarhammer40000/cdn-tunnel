package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBlockedIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "224.0.0.1", "::ffff:127.0.0.1"} {
		if !blockedIP(net.ParseIP(s)) {
			t.Errorf("%s должен быть запрещён", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"} {
		if blockedIP(net.ParseIP(s)) {
			t.Errorf("%s не должен блокироваться", s)
		}
	}
}

// Владелец ходит куда угодно, ссылка — только наружу.
func TestConnectSSRFPolicy(t *testing.T) {
	st = &stats{}
	echo := startEcho(t) // 127.0.0.1:port
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	post := func(link bool) int {
		authToken = "мастер"
		defer func() { authToken = "" }()
		req := httptest.NewRequest(http.MethodPost, "/t/connect?id=x"+randID(), strings.NewReader(echo))
		if !link {
			req.Header.Set(authHeader, "мастер")
		} else {
			req.Header.Set(linkHeader, issueCred("мастер"))
		}
		w := httptest.NewRecorder()
		ts.handleConnect(w, req)
		return w.Code
	}
	if c := post(false); c != http.StatusOK {
		t.Fatalf("владелец: %d, ожидался 200", c)
	}
	if c := post(true); c != http.StatusBadGateway {
		t.Fatalf("ссылка → loopback: %d, ожидался 502", c)
	}
	allowPrivate = true
	defer func() { allowPrivate = false }()
	if c := post(true); c != http.StatusOK {
		t.Fatalf("-allow-private: %d, ожидался 200", c)
	}
}

func TestPayloadLimit(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxPayload+1)
	req := httptest.NewRequest(http.MethodPost, "/hello", bytes.NewReader(big))
	if _, err := readPayload(req, qToken); err != errPayloadTooLarge {
		t.Fatalf("err=%v, ожидалась errPayloadTooLarge", err)
	}
	ok := httptest.NewRequest(http.MethodPost, "/hello", bytes.NewReader(big[:1000]))
	if b, err := readPayload(ok, qToken); err != nil || len(b) != 1000 {
		t.Fatalf("нормальное тело: %d байт, err=%v", len(b), err)
	}
}

func TestUpWindowAndDuplicates(t *testing.T) {
	st = &stats{}
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	s := &stream{id: "s", conn: c1, down: make(chan []byte, 1), done: make(chan struct{}), upBuf: map[uint64][]byte{}}
	s.upCond = sync.NewCond(&s.upMu)
	ts.streams["s"] = s
	up := func(seq string, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/t/up?id=s&seq="+seq, strings.NewReader(body))
		w := httptest.NewRecorder()
		ts.handleUp(w, req)
		return w.Code
	}
	if c := up("5000", "x"); c != http.StatusTooManyRequests {
		t.Fatalf("seq далеко впереди окна: %d, ожидался 429", c)
	}
	if c := up("3", "x"); c != http.StatusOK {
		t.Fatalf("seq в окне: %d", c)
	}
	s.upMu.Lock()
	n, b := len(s.upBuf), s.upBytes
	s.upMu.Unlock()
	if n != 1 || b != 1 {
		t.Fatalf("буфер: %d чанков, %d байт", n, b)
	}
	if c := up("3", "y"); c != http.StatusOK { // повтор того же seq
		t.Fatalf("дубль: %d", c)
	}
	s.upMu.Lock()
	n, b = len(s.upBuf), s.upBytes
	s.upMu.Unlock()
	if n != 1 || b != 1 {
		t.Fatalf("дубль задвоил буфер: %d чанков, %d байт", n, b)
	}
	close(s.done)
	s.upCond.Broadcast()
}

func TestNoStoreAndBanOnBruteforce(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	srv, _ := linkServer(t)
	get := func(key string) (*http.Response, int) {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/hello", nil)
		req.Header.Set(authHeader, key)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp, resp.StatusCode
	}
	resp, code := get("мастер")
	if code != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("владелец: %d, Cache-Control=%q", code, resp.Header.Get("Cache-Control"))
	}
	for i := 0; i < maxAuthFails; i++ {
		if _, c := get("не-то"); c != http.StatusNotFound {
			t.Fatalf("неверный ключ: %d", c)
		}
	}
	// Адрес в бане: даже верный ключ не проверяется.
	if _, c := get("мастер"); c != http.StatusNotFound {
		t.Fatalf("после бана верный ключ дал %d, ожидался 404", c)
	}
}

func TestAdminOnlyFromLoopback(t *testing.T) {
	authToken = "мастер"
	defer func() { authToken = "" }()
	mk := func(remote string, hdr ...string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, adminPath, nil)
		r.RemoteAddr = remote
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return r
	}
	if !adminAllowed(mk("127.0.0.1:5555")) {
		t.Error("localhost должен проходить")
	}
	if adminAllowed(mk("203.0.113.9:5555")) {
		t.Error("внешний адрес не должен проходить")
	}
	if adminAllowed(mk("127.0.0.1:5555", "Cf-Connecting-Ip", "1.2.3.4")) {
		t.Error("локальный прокси/туннель с заголовком CDN не должен проходить")
	}
	adminRemote = true
	defer func() { adminRemote = false }()
	if !adminAllowed(mk("203.0.113.9:5555")) {
		t.Error("-admin-remote должен пускать")
	}
}

func TestLimiterKeyUsesLastXFF(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.1:1"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
	if got := limiterKey(r); got != "203.0.113.7" {
		t.Fatalf("limiterKey=%q, ожидался последний элемент XFF", got)
	}
}

func TestFailGuardWindow(t *testing.T) {
	g := newFailGuard()
	now := time.Now()
	for i := 0; i < maxAuthFails; i++ {
		g.fail("a", now)
	}
	if !g.blocked("a", now.Add(time.Minute)) {
		t.Fatal("должен быть забанен")
	}
	if g.blocked("a", now.Add(authBanTime+time.Second)) {
		t.Fatal("бан должен истечь")
	}
	g.reset("a")
}
