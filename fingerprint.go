package main

// Маскировка TLS-отпечатка клиента под настоящий браузер (uTLS).
//
// Зачем: стандартный crypto/tls Go-клиента даёт легко узнаваемый JA3/JA4 —
// порядок расширений, наборов шифров и кривых у Go отличается от Chrome,
// Firefox и т.п. WAF/DPI перед CDN может фильтровать именно по этому
// отпечатку, независимо от того, что происходит внутри TLS-туннеля.
//
// Подход: один раз согласовываем ALPN настоящим отпечатком браузера (uTLS),
// затем в зависимости от результата ("h2" или "http/1.1") строим обычный
// http.Transport или golang.org/x/net/http2.Transport, но с DialTLSContext,
// который на каждое новое соединение делает TLS-рукопожатие через uTLS с тем
// же отпечатком. Сквозное шифрование (e2e.go) и это никак не пересекаются —
// оба слоя работают независимо и решают разные задачи: uTLS прячет форму
// TLS-рукопожатия, e2e.go прячет содержимое HTTP-тела от CDN.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Настройка (флаг -tls-fingerprint).
var tlsFingerprint = "chrome"

// tlsRootCAsOverride позволяет тестам подсунуть пул доверенных сертификатов
// тестового TLS-сервера. В проде всегда nil — используются системные корни,
// как у обычного TLS-клиента.
var tlsRootCAsOverride *x509.CertPool

// cdnAddr — адрес CDN на порту 443 для боевого пути (тесты дают свой ip:port
// напрямую в dialFingerprinted/negotiateALPN, минуя эту обёртку).
func cdnAddr(ip string) string { return net.JoinHostPort(ip, "443") }

// helloByName сопоставляет имя флага с отпечатком uTLS. "go" отключает uTLS
// целиком — используется штатный crypto/tls, как раньше (на случай, если
// перед CDN стоит что-то, что ломается именно на нестандартном ClientHello).
func helloByName(name string) (utls.ClientHelloID, bool) {
	switch strings.ToLower(name) {
	case "chrome":
		return utls.HelloChrome_Auto, true
	case "firefox":
		return utls.HelloFirefox_Auto, true
	case "safari":
		return utls.HelloSafari_Auto, true
	case "ios":
		return utls.HelloIOS_Auto, true
	case "edge":
		return utls.HelloEdge_Auto, true
	case "android":
		return utls.HelloAndroid_11_OkHttp, true
	case "random":
		return utls.HelloRandomized, true
	case "go", "off", "":
		return utls.ClientHelloID{}, false
	default:
		return utls.ClientHelloID{}, false
	}
}

// dialFingerprinted устанавливает TCP-соединение и делает TLS-рукопожатие
// через uTLS выбранным отпечатком. Возвращает уже готовое TLS-соединение —
// вызывающий сам решает, что с ним делать (обычный http.Transport или h2).
func dialFingerprinted(ctx context.Context, addr, host string, hello utls.ClientHelloID) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tuneConn(raw) // без Nagle + большие буферы, как и на обычном пути
	uc := utls.UClient(raw, &utls.Config{ServerName: host, RootCAs: tlsRootCAsOverride}, hello)
	if err := uc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("uTLS handshake: %w", err)
	}
	return uc, nil
}

// negotiateALPN делает разовое пробное рукопожатие, чтобы узнать, что выберет
// CDN — h2 или http/1.1 — с данным отпечатком. Дальше все реальные соединения
// пула строятся сразу под этот протокол, без пробы на каждое из них.
func negotiateALPN(ctx context.Context, addr, host string, hello utls.ClientHelloID) (string, error) {
	conn, err := dialFingerprinted(ctx, addr, host, hello)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	proto := conn.(*utls.UConn).ConnectionState().NegotiatedProtocol
	if proto == "" {
		proto = "http/1.1" // CDN не согласовал ALPN — обычный TLS без h2
	}
	return proto, nil
}

// buildCDNClient выбирает транспорт для одного соединения пула: с TLS-
// отпечатком браузера (uTLS) или обычный crypto/tls, если отпечаток выключен
// флагом -tls-fingerprint или проба не удалась (тогда — не молча: печатаем
// причину один раз на весь процесс и работаем как раньше).
func buildCDNClient(ip, host string) *http.Client {
	hello, ok := helloByName(tlsFingerprint)
	if !ok {
		if s := strings.ToLower(tlsFingerprint); s != "go" && s != "off" && s != "" {
			warnUnknownFingerprintOnce(tlsFingerprint)
		}
		return cdnClient(ip, host)
	}
	addr := cdnAddr(ip)
	alpn, err := fingerprintALPNOnce(addr, host, hello)
	if err != nil {
		warnFingerprintFailedOnce(err)
		return cdnClient(ip, host)
	}
	return fingerprintedClient(addr, host, alpn, hello)
}

var (
	fpOnce   sync.Once
	fpALPN   string
	fpErr    error
	warnOnce sync.Once
)

// fingerprintALPNOnce гоняет negotiateALPN один раз на процесс: ip/host у
// всего пула клиента одни и те же, а лишние TLS-рукопожатия только заметнее.
func fingerprintALPNOnce(addr, host string, hello utls.ClientHelloID) (string, error) {
	fpOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		fpALPN, fpErr = negotiateALPN(ctx, addr, host, hello)
	})
	return fpALPN, fpErr
}

func warnFingerprintFailedOnce(err error) {
	warnOnce.Do(func() {
		fmt.Printf("⚠ TLS-отпечаток (%s) не удался (%v) — использую обычный TLS Go для всех соединений\n", tlsFingerprint, err)
	})
}

func warnUnknownFingerprintOnce(name string) {
	warnOnce.Do(func() {
		fmt.Printf("⚠ неизвестный -tls-fingerprint=%q (варианты: chrome, firefox, safari, ios, edge, android, random, go) — использую обычный TLS Go\n", name)
	})
}

// alpn — результат negotiateALPN: определяет, какой транспорт (h2 или h1)
// строить; каждое новое соединение внутри него всё равно делает своё uTLS
// рукопожатие — согласованный на пробе ALPN лишь выбирает КАКОЙ транспорт
// использовать, а не переиспользует сам пробный конн.
func fingerprintedClient(addr, host, alpn string, hello utls.ClientHelloID) *http.Client {
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialFingerprinted(ctx, addr, host, hello)
	}
	if alpn == "h2" {
		tr := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dial(ctx, network, addr)
			},
			ReadIdleTimeout: 30 * time.Second,
		}
		return &http.Client{Transport: authRoundTripper{base: tr, id: clientID}}
	}
	tr := &http.Transport{
		DialTLSContext:      dial,
		DisableCompression:  true,
		IdleConnTimeout:     5 * time.Minute,
		WriteBufferSize:     64 * 1024,
		ReadBufferSize:      64 * 1024,
		MaxIdleConnsPerHost: 4,
	}
	return &http.Client{Transport: authRoundTripper{base: tr, id: clientID}}
}
