package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// tap записывает всё, что «видит CDN»: URL, заголовки, тела запросов и ответов.
type tap struct {
	mu    sync.Mutex
	all   bytes.Buffer
	hello [][]byte // тела рукопожатий (для replay-теста)
}

func (tp *tap) add(b []byte) {
	tp.mu.Lock()
	tp.all.Write(b)
	tp.mu.Unlock()
}

func (tp *tap) seen(sub []byte) bool {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return bytes.Contains(tp.all.Bytes(), sub)
}

type tapWriter struct {
	http.ResponseWriter
	tp *tap
}

func (w tapWriter) Write(b []byte) (int, error) { w.tp.add(b); return w.ResponseWriter.Write(b) }
func (w tapWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type tapReader struct {
	io.ReadCloser
	tp    *tap
	hello bool
	buf   bytes.Buffer
}

func (r *tapReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.tp.add(p[:n])
		if r.hello {
			r.buf.Write(p[:n])
		}
	}
	if err == io.EOF && r.hello {
		r.tp.mu.Lock()
		r.tp.hello = append(r.tp.hello, append([]byte(nil), r.buf.Bytes()...))
		r.tp.mu.Unlock()
	}
	return n, err
}

// e2eEnv — сервер с реестром, сессиями и «подслушивающим CDN» перед ним.
type e2eEnv struct {
	srv  *httptest.Server
	gate *linkGate
	ts   *tunnelServer
	tap  *tap
}

func resetE2EGlobals() {
	authToken, linkCred, deviceID = "", "", ""
	clientSess.Store(nil)
	requireE2E, clientLegacy = false, false
	clientNow = time.Now
	clientTransport, clientMethod, fastOpen = "chunked", "post", true
}

func newE2EEnv(t *testing.T, master string) *e2eEnv {
	t.Helper()
	resetE2EGlobals()
	t.Cleanup(resetE2EGlobals)
	authToken = master
	st = &stats{}
	serverMethod = "both"
	gate := newLinkGate()
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}, gate: gate}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", handleHello)
	mux.HandleFunc("/t/connect", ts.handleConnect)
	mux.HandleFunc("/t/down", ts.handleDown)
	mux.HandleFunc("/t/up", ts.handleUp)
	mux.HandleFunc("/t/ups", ts.handleUpStream)
	mux.HandleFunc("/t/close", ts.handleClose)
	mux.HandleFunc("/u/open", ts.handleUDPOpen)
	mux.HandleFunc("/u/down", ts.handleUDPDown)
	mux.HandleFunc("/u/send", ts.handleUDPSend)
	mux.HandleFunc("/u/close", ts.handleUDPClose)
	mux.HandleFunc("/bye", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	inner := gate.middleware(mux)

	tp := &tap{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hdr bytes.Buffer
		hdr.WriteString(r.Method + " " + r.URL.String() + "\n")
		r.Header.Write(&hdr)
		tp.add(hdr.Bytes())
		r.Body = &tapReader{ReadCloser: r.Body, tp: tp, hello: r.URL.Path == "/hello" && r.Header.Get(kxHeader) != ""}
		inner.ServeHTTP(tapWriter{w, tp}, r)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &e2eEnv{srv: srv, gate: gate, ts: ts, tap: tp}
}

func (e *e2eEnv) client() *tunnelClient {
	hc := &http.Client{Transport: authRoundTripper{base: e.srv.Client().Transport, id: "test"}}
	return &tunnelClient{base: e.srv.URL, pool: []*http.Client{hc}, udp: true}
}

func TestHKDFAndPBKDF2KnownAnswers(t *testing.T) {
	// RFC 5869, test case 1.
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	okm := hkdfExpand(hkdfExtract(salt, ikm), string(info), 42)
	if got := hex.EncodeToString(okm); got != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Fatalf("HKDF: %s", got)
	}
	// RFC 7914 / общеизвестные векторы PBKDF2-HMAC-SHA256.
	if got := hex.EncodeToString(pbkdf2([]byte("password"), []byte("salt"), 1, 32)); got != "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" {
		t.Fatalf("PBKDF2 c=1: %s", got)
	}
	if got := hex.EncodeToString(pbkdf2([]byte("password"), []byte("salt"), 2, 32)); got != "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43" {
		t.Fatalf("PBKDF2 c=2: %s", got)
	}
}

func TestRecordsRoundTripAndTamper(t *testing.T) {
	key := hkdfExpand([]byte("k"), "t", 32)
	a := newGCM(key)
	src := bytes.Repeat([]byte("привет-"), 10000)
	sr := newSealReader(bytes.NewReader(src), a, "aad")
	wire, _ := io.ReadAll(sr)
	got, err := io.ReadAll(newOpenReader(bytes.NewReader(wire), a, "aad"))
	if err != nil || !bytes.Equal(got, src) {
		t.Fatalf("round trip: err=%v, равны=%v", err, bytes.Equal(got, src))
	}
	bad := append([]byte(nil), wire...)
	bad[len(bad)/2] ^= 1
	if _, err := io.ReadAll(newOpenReader(bytes.NewReader(bad), a, "aad")); err == nil {
		t.Fatal("подмена записи не обнаружена")
	}
	if _, err := io.ReadAll(newOpenReader(bytes.NewReader(wire), a, "другой-aad")); err == nil {
		t.Fatal("чужой AAD принят")
	}
	// Перестановка записей местами (счётчик в nonce) тоже должна ломаться.
	r1 := sealRecord(a, 0, []byte("x"), []byte("one"))
	r2 := sealRecord(a, 1, []byte("x"), []byte("two"))
	if _, err := io.ReadAll(newOpenReader(bytes.NewReader(append(r2, r1...)), a, "x")); err == nil {
		t.Fatal("перестановка записей не обнаружена")
	}
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	for _, c := range []uint64{5, 3, 7, 6} {
		if !w.accept(c) {
			t.Fatalf("%d должен приниматься", c)
		}
	}
	for _, c := range []uint64{5, 3, 7} {
		if w.accept(c) {
			t.Fatalf("повтор %d принят", c)
		}
	}
	w.accept(1000)
	if w.accept(900) {
		t.Fatal("счётчик за окном принят")
	}
	if !w.accept(999) {
		t.Fatal("счётчик внутри окна отклонён")
	}
}

func TestE2EHandshakeOwner(t *testing.T) {
	e := newE2EEnv(t, "длинный-мастер-ключ")
	tc := e.client()
	if err := tc.helloE2E(); err != nil {
		t.Fatal(err)
	}
	if clientSess.Load() == nil {
		t.Fatal("сессия не создана")
	}
	// Сессионный запрос без секретов проходит.
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/hello", strings.NewReader("tok"))
	resp, err := tc.pool[0].Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(b) != helloPrefix+"tok" {
		t.Fatalf("ping в сессии: %d %q", resp.StatusCode, b)
	}
	if e.tap.seen([]byte("длинный-мастер-ключ")) || e.tap.seen([]byte(authHeader)) {
		t.Fatal("мастер-ключ или его заголовок виден на проводе")
	}
}

func TestE2EWrongKeyLooksLikeForeignSite(t *testing.T) {
	e := newE2EEnv(t, "правильный")
	tc := e.client()
	_, err := tc.clientKxWith(context.Background(), kxKindOwner, "", ownerPSK("неправильный"))
	if err == nil {
		t.Fatal("рукопожатие с чужим ключом прошло")
	}
	if errors.As(err, new(kxDeny)) {
		t.Fatalf("сервер выдал причину отказа тому, кто не знает ключ: %v", err)
	}
	// Ссылка, подписанная чужим мастер-ключом, тоже неотличима от «чужого сайта».
	fake := credMAC("другой-мастер", "deadbeefdeadbeef")
	_, err = tc.clientKxWith(context.Background(), kxKindLink, "deadbeefdeadbeef", linkPSK(fake))
	if err == nil || errors.As(err, new(kxDeny)) {
		t.Fatalf("поддельная ссылка: %v", err)
	}
}

func TestE2ELinkLifecycle(t *testing.T) {
	e := newE2EEnv(t, "мастер")
	rec := e.gate.issueLink("Андрею")
	cred := rec.ID + "." + credMAC("мастер", rec.ID)
	linkCred, deviceID = cred, "телефон-1"
	tc := e.client()
	if err := tc.helloE2E(); err != nil {
		t.Fatalf("ссылка не подключилась: %v", err)
	}
	if e.tap.seen([]byte(cred)) || e.tap.seen([]byte(credMAC("мастер", rec.ID))) {
		t.Fatal("удостоверение ссылки видно на проводе")
	}
	if e.tap.seen([]byte("телефон-1")) {
		t.Fatal("отпечаток устройства виден на проводе")
	}
	// Отзыв: уже открытая сессия получает отказ, новое рукопожатие — причину.
	e.gate.setRevoked(rec.ID, true)
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/hello", strings.NewReader("x"))
	resp, err := tc.pool[0].Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), denyRevoked) {
		t.Fatalf("сессия отозванной ссылки: %d %q", resp.StatusCode, body)
	}
	clientSess.Store(nil)
	var d kxDeny
	if _, err := tc.clientKx(context.Background()); !errors.As(err, &d) || d.reason != denyRevoked {
		t.Fatalf("рукопожатие по отозванной ссылке: %v", err)
	}
	// Другое устройство на занятой ссылке.
	e.gate.setRevoked(rec.ID, false)
	deviceID = "чужой-телефон"
	if _, err := tc.clientKx(context.Background()); !errors.As(err, &d) || d.reason != denyUsed {
		t.Fatalf("занятая ссылка: %v", err)
	}
}

func TestE2EClockSkewIsReported(t *testing.T) {
	e := newE2EEnv(t, "мастер")
	clientNow = func() time.Time { return time.Now().Add(10 * time.Minute) }
	var d kxDeny
	if _, err := e.client().clientKx(context.Background()); !errors.As(err, &d) || d.reason != denyClock {
		t.Fatalf("ожидалась причина %q, получено: %v", denyClock, err)
	}
}

func TestE2EReplayedHandshakeRejected(t *testing.T) {
	e := newE2EEnv(t, "мастер")
	tc := e.client()
	if err := tc.helloE2E(); err != nil {
		t.Fatal(err)
	}
	e.tap.mu.Lock()
	if len(e.tap.hello) == 0 {
		e.tap.mu.Unlock()
		t.Fatal("рукопожатие не перехвачено")
	}
	raw := e.tap.hello[0]
	e.tap.mu.Unlock()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/hello", bytes.NewReader(raw))
	req.Header.Set(kxHeader, "1")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("повтор рукопожатия принят: %d", resp.StatusCode)
	}
}

func TestE2ESocksThroughEncryption(t *testing.T) {
	marker := "СЕКРЕТНЫЙ-ТРАФИК-1234567890"
	cases := []struct {
		name, transport, method string
		fast                    bool
	}{
		{"chunked-post", "chunked", "post", true},
		{"chunked-get", "chunked", "get", false},
		{"stream", "stream", "post", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newE2EEnv(t, "мастер-ключ-для-e2e")
			echoHost, echoPort := splitAddr(t, startEcho(t))
			clientTransport, clientMethod, fastOpen = c.transport, c.method, c.fast
			tc := e.client()
			if err := tc.helloE2E(); err != nil {
				t.Fatal(err)
			}
			proxy, drain := socksProxy(t, tc)
			app := socksConnect(t, proxy, echoHost, echoPort)
			app.Write([]byte(marker))
			got := make([]byte, len(marker))
			if _, err := io.ReadFull(bufio.NewReader(app), got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != marker {
				t.Fatalf("эхо: %q", got)
			}
			app.Close()
			drain()
			for _, secret := range []string{marker, echoHost + ":", "мастер-ключ-для-e2e"} {
				if e.tap.seen([]byte(secret)) {
					t.Fatalf("на проводе виден открытый текст: %q", secret)
				}
			}
			// Адрес назначения тоже не должен читаться (в base64-виде для GET).
			if e.tap.seen([]byte(net.JoinHostPort(echoHost, itoa(echoPort)))) {
				t.Fatal("адрес назначения виден на проводе")
			}
		})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestE2EBulkTransfer(t *testing.T) {
	for _, tr := range []string{"chunked", "stream"} {
		t.Run(tr, func(t *testing.T) {
			e := newE2EEnv(t, "мастер")
			echoHost, echoPort := splitAddr(t, startEcho(t))
			clientTransport, clientMethod, fastOpen = tr, "post", true
			tc := e.client()
			if err := tc.helloE2E(); err != nil {
				t.Fatal(err)
			}
			proxy, drain := socksProxy(t, tc)
			app := socksConnect(t, proxy, echoHost, echoPort)
			const n = 4 << 20
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*31 + 7)
			}
			go func() { app.Write(src) }()
			got := make([]byte, n)
			if _, err := io.ReadFull(app, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, src) {
				t.Fatal("данные исказились")
			}
			app.Close()
			drain()
		})
	}
}

func TestE2ETamperedChunkRejected(t *testing.T) {
	e := newE2EEnv(t, "мастер")
	echo := startEcho(t)
	tc := e.client()
	if err := tc.helloE2E(); err != nil {
		t.Fatal(err)
	}
	hc := tc.pool[0]
	if err := tc.connect(hc, "tamper1", echo); err != nil {
		t.Fatal(err)
	}
	// Мусор вместо шифртекста и «чужой» seq — оба отклоняются.
	for _, seq := range []string{"0", "7"} {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/t/up?id=tamper1&seq="+seq, strings.NewReader("не-шифртекст-совсем-не-шифртекст"))
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("seq=%s: %d, ожидался 400", seq, resp.StatusCode)
		}
	}
	// Настоящий чанк с подменённым seq в URL не проходит (nonce и AAD привязаны к seq).
	k := tc.streamKeysFor("tamper1")
	ct := k.up.Seal(nil, nonceFor(0), []byte("данные"), upAAD("tamper1", 0, false))
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/t/up?id=tamper1&seq=1", bytes.NewReader(ct))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("переставленный seq принят: %d", resp.StatusCode)
	}
	// Повтор connect с тем же id не подменяет стрим.
	if err := tc.connect(hc, "tamper1", echo); err == nil {
		t.Fatal("повторный connect с тем же id принят")
	}
}

func TestRequireE2ERejectsLegacy(t *testing.T) {
	e := newE2EEnv(t, "мастер")
	requireE2E = true
	for _, path := range []string{"/hello", "/t/connect?id=x"} {
		req, _ := http.NewRequest(http.MethodPost, e.srv.URL+path, strings.NewReader("127.0.0.1:1"))
		req.Header.Set(authHeader, "мастер")
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s без E2E: %d, ожидался 404", path, resp.StatusCode)
		}
	}
	// А E2E-клиент работает.
	if err := e.client().helloE2E(); err != nil {
		t.Fatal(err)
	}
}

func TestE2EUDP(t *testing.T) {
	e := newE2EEnv(t, "мастер")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), a)
		}
	}()
	tc := e.client()
	if err := tc.helloE2E(); err != nil {
		t.Fatal(err)
	}
	hc := tc.pool[0]
	if err := tc.udpOpen(hc, "u1"); err != nil {
		t.Fatal(err)
	}
	defer tc.udpClose(hc, "u1")

	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/u/down?id=u1", nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	uk, _ := tc.ukeys.Load("u1")
	body := newOpenReader(resp.Body, uk.(*udpClientKeys).keys.down, "ud|u1")

	tc.udpSend(hc, "u1", encodeFrame(pc.LocalAddr().String(), []byte("UDP-СЕКРЕТ")))
	h := make([]byte, 2)
	if _, err := io.ReadFull(body, h); err != nil {
		t.Fatalf("down: %v", err)
	}
	addr := make([]byte, int(h[0])<<8|int(h[1]))
	io.ReadFull(body, addr)
	io.ReadFull(body, h)
	data := make([]byte, int(h[0])<<8|int(h[1]))
	io.ReadFull(body, data)
	if string(data) != "echo:UDP-СЕКРЕТ" {
		t.Fatalf("UDP эхо: %q", data)
	}
	if e.tap.seen([]byte("UDP-СЕКРЕТ")) {
		t.Fatal("UDP-данные видны на проводе")
	}
}
