package main

// Защитные помощники сервера: фильтр целей (SSRF), лимит перебора ключа,
// доступ к /admin только с самой машины.

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Лимиты на входящие данные.
const (
	maxPayload     = 4 << 20  // тело одного запроса (chunk/connect/udp), байт
	maxUpAhead     = 1024     // насколько seq может опережать уже записанный (chunked up)
	maxUpBufBytes  = 32 << 20 // сколько байт ждёт в реассемблере одного стрима
	maxAuthFails   = 10       // неудачных попыток ключа с одного адреса...
	authFailWindow = 5 * time.Minute
	authBanTime    = 15 * time.Minute
	maxGuardKeys   = 20000
)

// Флаги (заполняются в main).
var (
	allowPrivate bool // -allow-private: разрешить всем ходить во внутренние сети
	adminRemote  bool // -admin-remote: пускать /admin не только с localhost
)

var errBlockedTarget = errors.New("target not allowed")
var errPayloadTooLarge = errors.New("payload too large")

var blockedNets = mustCIDRs(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
)

func mustCIDRs(list ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, c := range list {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// blockedIP — адреса, куда обычному пользователю ссылки ходить нельзя:
// loopback, частные и link-local сети (в т.ч. метаданные облака 169.254.169.254).
func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range blockedNets {
			if n.Contains(v4) {
				return true
			}
		}
	}
	return false
}

// targetDialer — Dialer, который проверяет уже РАЗРЕШЁННЫЙ адрес прямо перед
// connect (защита от DNS rebinding). Владелец сервера ограничений не имеет.
func targetDialer(owner bool) *net.Dialer {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if owner || allowPrivate {
		return d
	}
	d.Control = func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil || blockedIP(net.ParseIP(host)) {
			return errBlockedTarget
		}
		return nil
	}
	return d
}

// udpTargetAllowed проверяет адрес назначения UDP-датаграммы.
func udpTargetAllowed(ua *net.UDPAddr, owner bool) bool {
	return owner || allowPrivate || !blockedIP(ua.IP)
}

// adminAllowed: панель открыта только запросам с самой машины (SSH → curl
// на localhost, как делает приложение) и без следов прокси/CDN в заголовках.
func adminAllowed(r *http.Request) bool {
	if adminRemote {
		return true
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(h); ip == nil || !ip.IsLoopback() {
		return false
	}
	for _, k := range []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip",
		"Cf-Connecting-Ip", "True-Client-Ip", "X-Forwarded-Host"} {
		if r.Header.Get(k) != "" {
			return false
		}
	}
	return true
}

// limiterKey — ключ для ограничения перебора. За CDN берём ПОСЛЕДНИЙ элемент
// X-Forwarded-For (его дописывает сам CDN; всё левее подделывает клиент).
// Это работает, только если origin закрыт файрволом для всех, кроме CDN.
func limiterKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.LastIndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[i+1:])
		}
		return strings.TrimSpace(xff)
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// failGuard считает неверные ключи по адресу и банит перебор.
type failGuard struct {
	mu sync.Mutex
	m  map[string]*failRec
}

type failRec struct {
	n     int
	first time.Time
	until time.Time
}

func newFailGuard() *failGuard { return &failGuard{m: map[string]*failRec{}} }

func (f *failGuard) blocked(k string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.m[k]
	return r != nil && now.Before(r.until)
}

func (f *failGuard) fail(k string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.m) >= maxGuardKeys {
		for key, r := range f.m { // чистим устаревшее; при переполнении — любые
			if now.After(r.until) && now.Sub(r.first) > authFailWindow {
				delete(f.m, key)
			}
		}
		if len(f.m) >= maxGuardKeys {
			return
		}
	}
	r := f.m[k]
	if r == nil || now.Sub(r.first) > authFailWindow {
		r = &failRec{first: now}
		f.m[k] = r
	}
	r.n++
	if r.n >= maxAuthFails {
		r.until = now.Add(authBanTime)
	}
}

func (f *failGuard) reset(k string) {
	f.mu.Lock()
	delete(f.m, k)
	f.mu.Unlock()
}
