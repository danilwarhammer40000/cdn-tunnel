package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetReliabilityGlobals() {
	maxDownRingBytes = 4 << 20
	maxDownReconnects = 8
	maxUpRetries = 4
}

// ---------------------------------------------------------------- dnRing

func TestDnRingBasicFlow(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	r := &dnRing{}
	// Пусто и не закрыто: poll(0) должен вернуть канал ожидания, не gone/closed.
	data, end, gone, closed, wait := r.poll(0)
	if len(data) != 0 || end != 0 || gone || closed || wait == nil {
		t.Fatalf("пустое кольцо: data=%v end=%d gone=%v closed=%v wait=%v", data, end, gone, closed, wait)
	}
	r.append([]byte("hello"))
	select {
	case <-wait:
	default:
		t.Fatal("append должен разбудить уже зарегистрированного ожидающего")
	}
	data, end, gone, closed, _ = r.poll(0)
	if string(data) != "hello" || end != 5 || gone || closed {
		t.Fatalf("после append: %q %d %v %v", data, end, gone, closed)
	}
	// Частичное чтение с середины.
	data, _, _, _, _ = r.poll(3)
	if string(data) != "lo" {
		t.Fatalf("poll(3) = %q, ожидалось \"lo\"", data)
	}
	r.append([]byte(" world"))
	data, end, _, _, _ = r.poll(5)
	if string(data) != " world" || end != 11 {
		t.Fatalf("после второго append: %q %d", data, end)
	}
	r.closeRing()
	_, _, gone, closed, wait = r.poll(11)
	if gone || !closed || wait != nil {
		t.Fatalf("на конце закрытого кольца: gone=%v closed=%v wait=%v", gone, closed, wait)
	}
}

func TestDnRingEviction(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	maxDownRingBytes = 10
	r := &dnRing{}
	r.append([]byte("0123456789")) // ровно на весь буфер
	r.append([]byte("ABCDE"))      // вытесняет первые 5 байт
	data, end, gone, _, _ := r.poll(0)
	if !gone {
		t.Fatalf("байты 0..5 должны быть вытеснены, а poll(0) вернул %q (end=%d)", data, end)
	}
	data, end, gone, _, _ = r.poll(5)
	if gone || string(data) != "56789ABCDE" || end != 15 {
		t.Fatalf("poll(5) = %q %d gone=%v, ожидалось \"56789ABCDE\" 15 false", data, end, gone)
	}
}

func TestDnRingWaiterRace(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	r := &dnRing{}
	const n = 2000
	var got []byte
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		var pos uint64
		for {
			data, end, gone, closed, wait := r.poll(pos)
			if gone {
				t.Error("неожиданный gone")
				close(done)
				return
			}
			if len(data) > 0 {
				mu.Lock()
				got = append(got, data...)
				mu.Unlock()
				pos = end
				continue
			}
			if closed {
				close(done)
				return
			}
			<-wait
		}
	}()
	for i := 0; i < n; i++ {
		r.append([]byte{byte(i)})
	}
	r.closeRing()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("таймаут — потребитель не догнал производителя")
	}
	if len(got) != n {
		t.Fatalf("получено %d байт, ожидалось %d", len(got), n)
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatalf("байт %d = %d, ожидалось %d (порядок нарушен)", i, b, byte(i))
		}
	}
}

// ---------------------------------------------------------------- handleDown resume

// newBareStream — минимальный stream для тестов handleDown без реального
// сокета цели (conn нужен только тем путям, что явно тестируются).
func newBareStream(id string) *stream {
	s := &stream{id: id, done: make(chan struct{}), dn: &dnRing{}, down: make(chan []byte, 16)}
	return s
}

func TestHandleDownResumeAfterClientDisconnect(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	s := newBareStream("r1")
	ts.streams["r1"] = s
	srv := httptest.NewServer(http.HandlerFunc(ts.handleDown))
	defer srv.Close()

	part1 := bytes.Repeat([]byte("A"), 100)
	part2 := bytes.Repeat([]byte("B"), 100)
	s.dn.append(part1)

	// Первый запрос читает только part1, затем клиент «обрывается» —
	// закрываем тело ответа раньше времени, не дожидаясь EOF.
	resp, err := http.Get(srv.URL + "?id=r1&from=0")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(part1))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, part1) {
		t.Fatalf("part1 не совпал")
	}
	resp.Body.Close() // «обрыв соединения»

	// Данные появляются уже после обрыва.
	s.dn.append(part2)

	// Второй запрос — с той же позиции, откуда оборвались.
	resp2, err := http.Get(srv.URL + "?id=r1&from=" + strconv.Itoa(len(part1)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	got2 := make([]byte, len(part2))
	if _, err := io.ReadFull(resp2.Body, got2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, part2) {
		t.Fatalf("part2 не совпал (данные потеряны или задвоены при resume)")
	}
}

func TestHandleDownGoneBeforeHeaders(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	maxDownRingBytes = 10
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	s := newBareStream("r2")
	ts.streams["r2"] = s
	srv := httptest.NewServer(http.HandlerFunc(ts.handleDown))
	defer srv.Close()

	s.dn.append(bytes.Repeat([]byte("X"), 10))
	s.dn.append(bytes.Repeat([]byte("Y"), 10)) // вытесняет всё, что было до этого

	resp, err := http.Get(srv.URL + "?id=r2&from=0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status=%d, ожидался 410 (диапазон уже вытеснен)", resp.StatusCode)
	}
}

func TestHandleDownBadFrom(t *testing.T) {
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	s := newBareStream("r3")
	ts.streams["r3"] = s
	srv := httptest.NewServer(http.HandlerFunc(ts.handleDown))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "?id=r3&from=не-число")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, ожидался 400", resp.StatusCode)
	}
}

func TestHandleDownTruncationTrailer(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	maxDownRingBytes = 10
	ts := &tunnelServer{streams: map[string]*stream{}, udp: map[string]*udpSession{}}
	s := newBareStream("r4")
	ts.streams["r4"] = s
	srv := httptest.NewServer(http.HandlerFunc(ts.handleDown))
	defer srv.Close()

	s.dn.append([]byte("hi")) // проходит gone-проверку до заголовков (0 < base=0)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"?id=r4&from=0", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, ожидался 200", resp.StatusCode)
	}
	// Пока хендлер ждёт продолжения, эвиктим всё вытеснением — это должно
	// закрыть тело с трейлером, а не просто чисто оборваться.
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.dn.append(bytes.Repeat([]byte("Z"), 20)) // вытесняет "hi" и ещё сверху — pos=2 гарантированно попадает в вытесненное
	}()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("тело: %v", err)
	}
	if string(got) != "hi" {
		t.Fatalf("тело=%q, ожидалось \"hi\"", got)
	}
	if resp.Trailer.Get(downTruncatedTrailer) == "" {
		t.Fatal("ожидался трейлер об обрезанном потоке — клиент не должен принять это за штатный конец")
	}
}

// ---------------------------------------------------------------- клиентский relayDown/up

// flakyDownRT обрывает /t/down ответ после нескольких байт первые N раз, чтобы
// проверить реальный reconnect клиента через настоящий HTTP-стек.
type flakyDownRT struct {
	base      http.RoundTripper
	failFirst int32
}

type cutBody struct {
	io.ReadCloser
	n     int
	after int
}

func (c *cutBody) Read(p []byte) (int, error) {
	if c.n >= c.after {
		return 0, io.ErrUnexpectedEOF
	}
	if len(p) > c.after-c.n {
		p = p[:c.after-c.n]
	}
	n, err := c.ReadCloser.Read(p)
	c.n += n
	return n, err
}

func (f *flakyDownRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := f.base.RoundTrip(r)
	if err != nil || !strings.Contains(r.URL.Path, "/t/down") {
		return resp, err
	}
	if atomic.AddInt32(&f.failFirst, -1) >= 0 {
		resp.Body = &cutBody{ReadCloser: resp.Body, after: 37} // произвольная маленькая граница
	}
	return resp, err
}

func TestClientResumesAfterRealDisconnect(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	for _, tr := range []string{"chunked", "stream"} {
		for _, useE2E := range []bool{false, true} {
			name := tr
			if useE2E {
				name += "-e2e"
			}
			t.Run(name, func(t *testing.T) {
				resetReliabilityGlobals()
				clientTransport, clientMethod, fastOpen = tr, "post", true
				var tc *tunnelClient
				var baseTransport http.RoundTripper
				echoHost, echoPort := splitAddr(t, startEcho(t))
				if useE2E {
					e := newE2EEnv(t, "мастер-резюм")
					tc = e.client()
					if err := tc.helloE2E(); err != nil {
						t.Fatal(err)
					}
					baseTransport = tc.pool[0].Transport
				} else {
					st = &stats{}
					serverMethod = "both"
					srv, hc := newTestServer(t)
					tc = &tunnelClient{base: srv.URL, pool: []*http.Client{hc}}
					baseTransport = hc.Transport
				}
				flaky := &flakyDownRT{base: baseTransport, failFirst: 3}
				tc.pool[0] = &http.Client{Transport: flaky}

				proxy, drain := socksProxy(t, tc)
				app := socksConnect(t, proxy, echoHost, echoPort)
				const size = 512 * 1024
				payload := make([]byte, size)
				rand.Read(payload)
				go func() { app.Write(payload) }()
				got := make([]byte, size)
				if _, err := io.ReadFull(app, got); err != nil {
					t.Fatalf("read: %v", err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("данные исказились после переподключений (потеря/задвоение/перестановка)")
				}
				app.Close()
				drain()
			})
		}
	}
}

// ---------------------------------------------------------------- up-ретраи

func TestUpRetriesOnServerErrorNotOnBadRequest(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	maxUpRetries = 3
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tc := &tunnelClient{base: srv.URL}
	clientMethod = "post"
	if err := tc.up(srv.Client(), "x", 0, []byte("data")); err != nil {
		t.Fatalf("после ретраев ожидался успех: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("вызовов: %d, ожидалось 3 (2 неудачи + успех)", got)
	}

	atomic.StoreInt32(&calls, 0)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv2.Close()
	tc2 := &tunnelClient{base: srv2.URL}
	if err := tc2.up(srv2.Client(), "x", 0, []byte("data")); err == nil {
		t.Fatal("400 должен вернуть ошибку")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("400 не должен повторяться, вызовов: %d", got)
	}
}

// ---------------------------------------------------------------- half-close

// startHalfCloseTarget — сервер, который читает вход до EOF (это и есть
// половинное закрытие), затем один раз отвечает и держит соединение живым.
func startHalfCloseTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(io.Discard, c) // ждём EOF на чтение
		c.Write([]byte("реплика после половинного закрытия"))
		time.Sleep(2 * time.Second)
	}()
	return ln.Addr().String()
}

func TestHalfCloseLetsTargetReply(t *testing.T) {
	for _, tr := range []string{"chunked", "stream"} {
		t.Run(tr, func(t *testing.T) {
			resetReliabilityGlobals()
			st = &stats{}
			serverMethod, clientMethod, clientTransport, fastOpen = "both", "post", tr, true
			srv, hc := newTestServer(t)
			tc := &tunnelClient{base: srv.URL, pool: []*http.Client{hc}}
			targetHost, targetPort := splitAddr(t, startHalfCloseTarget(t))

			proxy, drain := socksProxy(t, tc)
			app := socksConnect(t, proxy, targetHost, targetPort)

			cw, ok := app.(interface{ CloseWrite() error })
			if !ok {
				t.Fatal("тестовое соединение не поддерживает половинное закрытие")
			}
			app.Write([]byte("запрос от приложения"))
			if err := cw.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			buf := make([]byte, 4096)
			n, err := app.Read(buf)
			if err != nil {
				t.Fatalf("после половинного закрытия ответ не пришёл: %v", err)
			}
			if string(buf[:n]) != "реплика после половинного закрытия" {
				t.Fatalf("ответ=%q", buf[:n])
			}
			app.Close()
			drain()
		})
	}
}

func TestUpEOFAuthenticatedUnderE2E(t *testing.T) {
	t.Cleanup(resetReliabilityGlobals)
	e := newE2EEnv(t, "мастер-eof")
	tc := e.client()
	if err := tc.helloE2E(); err != nil {
		t.Fatal(err)
	}
	echo := startEcho(t)
	hc := tc.pool[0]
	if err := tc.connect(hc, "eof1", echo); err != nil {
		t.Fatal(err)
	}
	k := tc.streamKeysFor("eof1")
	// Настоящий eof-маркер для seq=0 (никаких данных ещё не посылали).
	realCT := k.up.Seal(nil, nonceFor(0), nil, upAAD("eof1", 0, true))
	// Пытаемся подсунуть его как ОБЫЧНЫЙ чанк (eof=0 в URL) — AAD не совпадёт.
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/t/up?id=eof1&seq=0", bytes.NewReader(realCT))
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("eof-запись, поданная как обычный чанк: %d, ожидался 400 (узел не может просто дописать &eof=1 или снять его)", resp.StatusCode)
	}
	// А как настоящий eof-запрос — проходит.
	req2, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/t/up?id=eof1&seq=0&eof=1", bytes.NewReader(realCT))
	resp2, err := hc.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("настоящий eof-маркер: %d", resp2.StatusCode)
	}
}
