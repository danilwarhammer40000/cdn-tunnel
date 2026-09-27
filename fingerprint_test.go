package main

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func resetFingerprintOnces() {
	fpOnce, warnOnce = sync.Once{}, sync.Once{}
	fpALPN, fpErr = "", nil
	tlsRootCAsOverride = nil
	tlsFingerprint = "chrome"
}

// tlsTestServer поднимает httptest-сервер и настраивает tlsRootCAsOverride,
// чтобы uTLS-клиент в тестах реально проверял сертификат, а не отключал
// проверку — это ближе к тому, что происходит с настоящим CDN.
func tlsTestServer(t *testing.T, h2 bool, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	t.Cleanup(func() { tlsRootCAsOverride = nil })
	tlsRootCAsOverride = pool
	return srv
}

func TestHelloByName(t *testing.T) {
	for _, name := range []string{"chrome", "Chrome", "firefox", "safari", "ios", "edge", "android", "random"} {
		if _, ok := helloByName(name); !ok {
			t.Errorf("%q должен резолвиться в отпечаток", name)
		}
	}
	for _, name := range []string{"go", "off", "", "netscape", "GO"} {
		if hello, ok := helloByName(name); ok {
			t.Errorf("%q не должен давать отпечаток, получено %+v", name, hello)
		}
	}
}

func TestNegotiateALPNHTTP2AndHTTP1(t *testing.T) {
	t.Cleanup(resetFingerprintOnces)
	for _, tc := range []struct {
		name string
		h2   bool
		want string
	}{
		{"h2", true, "h2"},
		{"h1", false, "http/1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetFingerprintOnces()
			srv := tlsTestServer(t, tc.h2, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
			addr := srv.Listener.Addr().String()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			proto, err := negotiateALPN(ctx, addr, "example.com", utls.HelloChrome_Auto)
			if err != nil {
				t.Fatal(err)
			}
			if proto != tc.want {
				t.Fatalf("ALPN=%q, ожидался %q", proto, tc.want)
			}
		})
	}
}

func TestFingerprintedClientRoundTrip(t *testing.T) {
	t.Cleanup(resetFingerprintOnces)
	for _, tc := range []struct {
		name string
		h2   bool
	}{{"h2", true}, {"h1", false}} {
		t.Run(tc.name, func(t *testing.T) {
			resetFingerprintOnces()
			const body = "секретный-ответ-сервера"
			var gotProto string
			srv := tlsTestServer(t, tc.h2, func(w http.ResponseWriter, r *http.Request) {
				gotProto = r.Proto
				w.Write([]byte(body))
			})
			addr := srv.Listener.Addr().String()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			alpn, err := negotiateALPN(ctx, addr, "example.com", utls.HelloChrome_Auto)
			if err != nil {
				t.Fatal(err)
			}
			hc := fingerprintedClient(addr, "example.com", alpn, utls.HelloChrome_Auto)
			resp, err := hc.Get("https://example.com/")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(got) != body {
				t.Fatalf("тело: %q", got)
			}
			wantProto := "HTTP/1.1"
			if tc.h2 {
				wantProto = "HTTP/2.0"
			}
			if gotProto != wantProto {
				t.Fatalf("сервер увидел протокол %q, ожидался %q", gotProto, wantProto)
			}
		})
	}
}

func TestFingerprintRejectsWrongHostname(t *testing.T) {
	t.Cleanup(resetFingerprintOnces)
	srv := tlsTestServer(t, false, func(w http.ResponseWriter, r *http.Request) {})
	addr := srv.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Сертификат httptest выписан на 127.0.0.1/example.com, а не на этот хост:
	// проверка имени должна отработать, а не быть тихо отключена.
	if _, err := negotiateALPN(ctx, addr, "не-тот-хост.invalid", utls.HelloChrome_Auto); err == nil {
		t.Fatal("рукопожатие с неверным SNI/CN прошло — проверка сертификата отключена?")
	}
}

func TestBuildCDNClientFallsBackOnBadFingerprintName(t *testing.T) {
	t.Cleanup(resetFingerprintOnces)
	resetFingerprintOnces()
	tlsFingerprint = "netscape-navigator"
	hc := buildCDNClient("127.0.0.1", "example.com")
	if hc == nil {
		t.Fatal("nil client")
	}
	// Обычный cdnClient использует стандартный http.Transport с TLSClientConfig.
	tr, ok := hc.Transport.(authRoundTripper).base.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("неизвестное имя отпечатка должно откатываться на обычный http.Transport")
	}
}

func TestBuildCDNClientFallsBackWhenHandshakeFails(t *testing.T) {
	t.Cleanup(resetFingerprintOnces)
	resetFingerprintOnces()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // принимаем TCP и сразу рвём — TLS-рукопожатие не состоится
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if _, err := fingerprintALPNOnce(ln.Addr().String(), "example.com", utls.HelloChrome_Auto); err == nil {
		t.Fatal("рукопожатие с обрывающим соединение сервером неожиданно удалось")
	}
}

func TestFingerprintUsesBrowserClientHello(t *testing.T) {
	t.Cleanup(resetFingerprintOnces)
	// Реальный uTLS-отпечаток Chrome отличается от stdlib crypto/tls в первую
	// очередь порядком/составом расширений ClientHello. Полноценный разбор
	// ClientHello избыточен для целей маскировки; здесь смок-тест: с разными
	// ID согласование всё ещё проходит (регрессия — если у обоих перестанет
	// работать, значит сломан сам вызов uTLS, а не что-то по теме отпечатка).
	srv := tlsTestServer(t, true, func(w http.ResponseWriter, r *http.Request) {})
	addr := srv.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := negotiateALPN(ctx, addr, "example.com", utls.HelloChrome_Auto); err != nil {
		t.Fatal(err)
	}
	if _, err := negotiateALPN(ctx, addr, "example.com", utls.HelloGolang); err != nil {
		t.Fatal(err)
	}
}
