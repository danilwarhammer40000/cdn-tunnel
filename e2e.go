package main

// Сквозное шифрование клиент↔origin поверх HTTP через CDN.
//
// Зачем: CDN терминирует TLS и без этого слоя видит мастер-ключ/ссылку в
// заголовках, адреса назначения и весь трафик открытым текстом.
//
// Схема (аналог Noise NNpsk0 на примитивах стандартной библиотеки):
//   - обе стороны знают секрет PSK, который НИКОГДА не ходит по сети:
//     владелец — из мастер-пароля (PBKDF2), ссылка — из своей подписи cred;
//   - клиент шлёт эфемерный X25519 + метку времени + nonce + MAC по PSK;
//   - сервер проверяет MAC (значит, клиент знает PSK), отвечает своим
//     эфемерным ключом и MAC по PSK (значит, сервер знает PSK);
//   - ключи c2s/s2c = HKDF(X25519 || PSK, транскрипт): forward secrecy от
//     эфемерных ключей, аутентификация обеих сторон от PSK;
//   - дальше каждый стрим получает свои подключи, данные едут AES-256-GCM.
//
// Ограничение: PSK владельца получен из пароля, поэтому слабый пароль можно
// перебирать офлайн по записанному рукопожатию. Берите длинный случайный
// мастер-ключ; ссылки (128-битная подпись) от этого не страдают.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	kxHeader  = "X-Tunnel-Kx"  // «это рукопожатие E2E» (значение — версия)
	sidHeader = "X-Tunnel-Sid" // идентификатор сессии (не секрет: без ключей он бесполезен)
	kxVer     = 1

	kxKindOwner = 0
	kxKindLink  = 1

	kxMaxSkew      = 2 * time.Minute
	sessIdleTTL    = 15 * time.Minute
	maxSessions    = 4096
	maxSessPerKey  = 64
	maxRecord      = 1<<20 + 16 // потолок записи вниз (защита клиента от чужой длины)
	udpReplayBits  = 64
	denyClock      = "clock skew"
	pbkdf2Iter     = 100000
	pskLabelOwner  = "cdn-tunnel/e2e/v1/owner"
	pskLabelLink   = "cdn-tunnel/e2e/v1/link"
	labelK0        = "cdn-tunnel/e2e/v1/k0"
	sidBytes       = 16
	nonceBytes     = 16
	x25519Len      = 32
	macLen         = 32
	kxClientPrefix = "cdn-tunnel/e2e/v1/c1"
	kxServerPrefix = "cdn-tunnel/e2e/v1/s1"
)

// Настройки режима (флаги).
var (
	requireE2E   bool // сервер: отвергать запросы без E2E-сессии (-require-e2e)
	clientLegacy bool // клиент: работать по-старому, без E2E (-legacy)
)

var errKx = errors.New("e2e: handshake failed")

// clientNow — часы клиента для метки времени рукопожатия (подменяются в тестах).
var clientNow = time.Now

// ---------------------------------------------------------------- примитивы

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk []byte, info string, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write([]byte(info))
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// pbkdf2 — PBKDF2-HMAC-SHA256 (в стандартной библиотеке нет до Go 1.24).
func pbkdf2(pass, salt []byte, iter, n int) []byte {
	var out []byte
	for block := uint32(1); len(out) < n; block++ {
		m := hmac.New(sha256.New, pass)
		m.Write(salt)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], block)
		m.Write(b[:])
		u := m.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			m = hmac.New(sha256.New, pass)
			m.Write(u)
			u = m.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:n]
}

var (
	pskMu    sync.Mutex
	pskCache = map[string][]byte{}
)

// ownerPSK — секрет владельца из мастер-пароля (медленный KDF, результат кэшируется).
func ownerPSK(master string) []byte {
	pskMu.Lock()
	defer pskMu.Unlock()
	if k, ok := pskCache[master]; ok {
		return k
	}
	k := pbkdf2([]byte(master), []byte(pskLabelOwner), pbkdf2Iter, 32)
	pskCache[master] = k
	return k
}

// linkPSK — секрет ссылки из её подписи (128 бит энтропии, KDF не нужен).
func linkPSK(mac string) []byte {
	m := hmac.New(sha256.New, []byte(mac))
	m.Write([]byte(pskLabelLink))
	return m.Sum(nil)
}

func newGCM(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return g
}

// subAEAD — подключ под метку: у каждого стрима/направления/назначения свой.
func subAEAD(base []byte, label string) cipher.AEAD {
	return newGCM(hkdfExpand(base, label, 32))
}

// nonceFor — 96-битный nonce из 64-битного счётчика. Уникальность гарантируется
// тем, что под каждым подключом счётчик никогда не повторяется.
func nonceFor(ctr uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// ---------------------------------------------------------------- записи

// sealReader превращает поток в последовательность записей [len u32][ct].
type sealReader struct {
	r    io.Reader
	aead cipher.AEAD
	aad  []byte
	ctr  uint64
	pend []byte
	tmp  []byte
	err  error
}

func newSealReader(r io.Reader, a cipher.AEAD, aad string) *sealReader {
	return &sealReader{r: r, aead: a, aad: []byte(aad), tmp: make([]byte, 16*1024)}
}

func (s *sealReader) Read(p []byte) (int, error) {
	for len(s.pend) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		n, err := s.r.Read(s.tmp)
		s.err = err
		if n > 0 {
			s.pend = sealRecord(s.aead, s.ctr, s.aad, s.tmp[:n])
			s.ctr++
		}
	}
	n := copy(p, s.pend)
	s.pend = s.pend[n:]
	return n, nil
}

func sealRecord(a cipher.AEAD, ctr uint64, aad, pt []byte) []byte {
	out := make([]byte, 4, 4+len(pt)+a.Overhead())
	out = a.Seal(out, nonceFor(ctr), pt, aad)
	binary.BigEndian.PutUint32(out[:4], uint32(len(out)-4))
	return out
}

// openReader читает записи [len u32][ct] и отдаёт открытый текст.
type openReader struct {
	r        io.Reader
	aead     cipher.AEAD
	aad      []byte
	ctr      uint64
	pend     []byte
	consumed uint64 // байт прочитано из r ЦЕЛЫМИ записями — точка для resume
}

// Consumed — сколько байт нижележащего потока разобрано в полные, успешно
// расшифрованные записи. Используется клиентом для возобновления down-GET
// с точной границы записи после обрыва (см. relayDown в reliability.go).
func (o *openReader) Consumed() uint64 { return o.consumed }

func newOpenReader(r io.Reader, a cipher.AEAD, aad string) *openReader {
	return &openReader{r: r, aead: a, aad: []byte(aad)}
}

func (o *openReader) Read(p []byte) (int, error) {
	for len(o.pend) == 0 {
		var h [4]byte
		if _, err := io.ReadFull(o.r, h[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(h[:])
		if n < uint32(o.aead.Overhead()) || n > maxRecord {
			return 0, errors.New("e2e: bad record length")
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(o.r, ct); err != nil {
			return 0, err
		}
		pt, err := o.aead.Open(nil, nonceFor(o.ctr), ct, o.aad)
		if err != nil {
			return 0, errors.New("e2e: record authentication failed")
		}
		o.ctr++
		o.consumed += uint64(len(h) + len(ct))
		o.pend = pt
	}
	n := copy(p, o.pend)
	o.pend = o.pend[n:]
	return n, nil
}

// ---------------------------------------------------------------- сессия

// streamKeys — подключи одного TCP-стрима (одинаково выводятся с обеих сторон).
type streamKeys struct {
	connect cipher.AEAD // c2s: цель connect (nonce 0)
	up      cipher.AEAD // c2s: чанки chunked-режима (nonce = seq)
	ups     cipher.AEAD // c2s: записи потокового апстрима
	down    cipher.AEAD // s2c: записи вниз
	id      string
}

func deriveStreamKeys(c2s, s2c []byte, id string) *streamKeys {
	return &streamKeys{
		id:      id,
		connect: subAEAD(c2s, "cn|"+id),
		up:      subAEAD(c2s, "up|"+id),
		ups:     subAEAD(c2s, "ups|"+id),
		down:    subAEAD(s2c, "dn|"+id),
	}
}

// upAAD различает обычный чанк и маркер конца загрузки (eof=true) — иначе
// узел на пути мог бы просто дописать "&eof=1" в URL уже подписанного
// запроса и оборвать чужую загрузку раньше времени без знания ключа.
func upAAD(id string, seq uint64, eof bool) []byte {
	if eof {
		return []byte(fmt.Sprintf("up|%s|%d|eof", id, seq))
	}
	return []byte(fmt.Sprintf("up|%s|%d", id, seq))
}

// udpKeys — подключи UDP-сессии.
type udpKeys struct {
	up   cipher.AEAD // c2s: пачки датаграмм (nonce = счётчик пачки)
	down cipher.AEAD // s2c: записи вниз
	id   string
}

func deriveUDPKeys(c2s, s2c []byte, id string) *udpKeys {
	return &udpKeys{id: id, up: subAEAD(c2s, "uu|"+id), down: subAEAD(s2c, "ud|"+id)}
}

// replayWindow — скользящее окно принятых счётчиков (UDP-пачки приходят вразнобой).
type replayWindow struct {
	mu   sync.Mutex
	max  uint64
	bits uint64
	init bool
}

func (w *replayWindow) accept(c uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init {
		w.init, w.max, w.bits = true, c, 1
		return true
	}
	switch {
	case c > w.max:
		shift := c - w.max
		if shift >= udpReplayBits {
			w.bits = 1
		} else {
			w.bits = w.bits<<shift | 1
		}
		w.max = c
		return true
	case w.max-c >= udpReplayBits:
		return false
	default:
		bit := uint64(1) << (w.max - c)
		if w.bits&bit != 0 {
			return false
		}
		w.bits |= bit
		return true
	}
}

// ---------------------------------------------------------------- сервер

// e2eSession — состояние одной сессии на сервере.
type e2eSession struct {
	sid      string
	c2s, s2c []byte
	owner    bool
	linkID   string
	device   string
	created  time.Time
	last     time.Time
}

func (s *e2eSession) billKey() string {
	if s.owner {
		return ownerKey
	}
	return s.linkID
}

type sessionStore struct {
	mu     sync.Mutex
	m      map[string]*e2eSession
	nonces map[[nonceBytes]byte]time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: map[string]*e2eSession{}, nonces: map[[nonceBytes]byte]time.Time{}}
}

func (ss *sessionStore) get(sid string, now time.Time) *e2eSession {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.m[sid]
	if s == nil {
		return nil
	}
	if now.Sub(s.last) > sessIdleTTL {
		delete(ss.m, sid)
		return nil
	}
	s.last = now
	return s
}

// add заводит сессию; при переполнении вытесняет самые старые.
func (ss *sessionStore) add(s *e2eSession, now time.Time) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	perKey, oldest := 0, (*e2eSession)(nil)
	for id, o := range ss.m {
		if now.Sub(o.last) > sessIdleTTL {
			delete(ss.m, id)
			continue
		}
		if o.billKey() == s.billKey() {
			perKey++
			if oldest == nil || o.last.Before(oldest.last) {
				oldest = o
			}
		}
	}
	if perKey >= maxSessPerKey && oldest != nil {
		delete(ss.m, oldest.sid)
	}
	if len(ss.m) >= maxSessions {
		var old *e2eSession
		for _, o := range ss.m {
			if old == nil || o.last.Before(old.last) {
				old = o
			}
		}
		if old != nil {
			delete(ss.m, old.sid)
		}
	}
	s.created, s.last = now, now
	ss.m[s.sid] = s
}

// fresh запоминает nonce клиента; повтор внутри окна — replay.
func (ss *sessionStore) fresh(n [nonceBytes]byte, now time.Time) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for k, t := range ss.nonces {
		if now.Sub(t) > 2*kxMaxSkew+time.Minute {
			delete(ss.nonces, k)
		}
	}
	if _, dup := ss.nonces[n]; dup {
		return false
	}
	if len(ss.nonces) > 100000 {
		return false
	}
	ss.nonces[n] = now
	return true
}

type ctxKey struct{}

func sessFrom(r *http.Request) *e2eSession {
	s, _ := r.Context().Value(ctxKey{}).(*e2eSession)
	return s
}

func withSess(r *http.Request, s *e2eSession) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, s))
}

// parsedHello — разобранное сообщение клиента.
type parsedHello struct {
	kind   byte
	id     string
	cEph   []byte
	nc     [nonceBytes]byte
	ts     int64
	enc    []byte
	mac    []byte
	signed []byte // всё, что покрыто MAC
	raw    []byte
}

func parseClientHello(b []byte) (*parsedHello, error) {
	// ver kind idLen id cEph nc ts encLen enc mac
	if len(b) < 3 || b[0] != kxVer {
		return nil, errKx
	}
	h := &parsedHello{kind: b[1], raw: b}
	il := int(b[2])
	off := 3
	if len(b) < off+il+x25519Len+nonceBytes+8+2+macLen {
		return nil, errKx
	}
	h.id = string(b[off : off+il])
	off += il
	h.cEph = b[off : off+x25519Len]
	off += x25519Len
	copy(h.nc[:], b[off:off+nonceBytes])
	off += nonceBytes
	h.ts = int64(binary.BigEndian.Uint64(b[off : off+8]))
	off += 8
	el := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if len(b) != off+el+macLen {
		return nil, errKx
	}
	h.enc = b[off : off+el]
	off += el
	h.signed = b[:off]
	h.mac = b[off:]
	return h, nil
}

func kxMAC(psk []byte, prefix string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte(prefix))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// k0 — ключ «предрукопожатия»: шифрует device клиента и причину отказа сервера.
func k0(psk []byte, nc [nonceBytes]byte) cipher.AEAD {
	return newGCM(hkdfExpand(hkdfExtract(nc[:], psk), labelK0, 32))
}

// handleKx обрабатывает POST/GET /hello с заголовком X-Tunnel-Kx.
func (g *linkGate) handleKx(w http.ResponseWriter, r *http.Request) {
	fail := func() { g.guard.fail(limiterKey(r), time.Now()); http.NotFound(w, r) }
	if authToken == "" || !methodAllowed(r) {
		http.NotFound(w, r) // без мастер-ключа нет общего секрета
		return
	}
	raw, err := readPayload(r, qToken)
	if err != nil {
		fail()
		return
	}
	h, err := parseClientHello(raw)
	if err != nil {
		fail()
		return
	}
	var psk []byte
	switch h.kind {
	case kxKindOwner:
		psk = ownerPSK(authToken)
	case kxKindLink:
		psk = linkPSK(credMAC(authToken, h.id))
	default:
		fail()
		return
	}
	// 1) клиент обязан знать PSK — иначе неотличимо от чужого сайта.
	if !hmac.Equal(h.mac, kxMAC(psk, kxClientPrefix, h.signed)) {
		fail()
		return
	}
	g.guard.reset(limiterKey(r))
	now := time.Now()
	k := k0(psk, h.nc)
	reply := func(reason string) { // отказ для владельца PSK: причина шифруется
		ct := k.Seal(nil, nonceFor(1), []byte(reason), h.mac)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusForbidden)
		w.Write(ct)
	}
	// 2) свежесть: метка времени и одноразовость nonce.
	if d := now.Sub(time.Unix(h.ts, 0)); d > kxMaxSkew || d < -kxMaxSkew {
		reply(denyClock)
		return
	}
	if !g.sess.fresh(h.nc, now) {
		fail() // повтор чужого рукопожатия
		return
	}
	// 3) устройство клиента (зашифровано под k0).
	device := ""
	if len(h.enc) > 0 {
		pt, err := k.Open(nil, nonceFor(0), h.enc, h.signed[:3+len(h.id)])
		if err != nil {
			fail()
			return
		}
		device = string(pt)
	}
	// 4) реестр ссылок — последнее слово за ним.
	sess := &e2eSession{owner: h.kind == kxKindOwner, linkID: h.id, device: device}
	if sess.owner {
		g.seen(ownerKey, clientIP(r))
	} else if _, ok, why := g.useLink(h.id, device, clientIP(r)); !ok {
		reply(why)
		return
	}
	// 5) ответ сервера и ключи.
	curve := ecdh.X25519()
	sPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	cPub, err := curve.NewPublicKey(h.cEph)
	if err != nil {
		fail()
		return
	}
	dh, err := sPriv.ECDH(cPub)
	if err != nil {
		fail()
		return
	}
	var ns [nonceBytes]byte
	rand.Read(ns[:])
	sidRaw := make([]byte, sidBytes)
	rand.Read(sidRaw)
	sess.sid = hex.EncodeToString(sidRaw)
	sBody := append(append(append([]byte{}, sPriv.PublicKey().Bytes()...), ns[:]...), sidRaw...)
	th := sha256.Sum256(append(append([]byte{}, h.raw...), sBody...))
	prk := hkdfExtract(append(h.nc[:], ns[:]...), append(append([]byte{}, dh...), psk...))
	sess.c2s = hkdfExpand(prk, "c2s|"+string(th[:]), 32)
	sess.s2c = hkdfExpand(prk, "s2c|"+string(th[:]), 32)
	mac := kxMAC(psk, kxServerPrefix, th[:])
	g.sess.add(sess, now)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(append(sBody, mac...))
}

// ---------------------------------------------------------------- клиент

// clientSession — состояние E2E-сессии на клиенте.
type clientSession struct {
	sid      string
	c2s, s2c []byte
}

// kxDeny — отказ сервера при рукопожатии (причина расшифрована).
type kxDeny struct{ reason string }

func (d kxDeny) Error() string { return d.reason }

// clientKx выполняет рукопожатие. psk и kind определяются заранее.
func (tc *tunnelClient) clientKx(ctx context.Context) (*clientSession, error) {
	var psk []byte
	var kind byte
	var id string
	switch {
	case linkCred != "":
		i := strings.IndexByte(linkCred, '.')
		if i <= 0 {
			return nil, errors.New("некорректная ссылка (cred)")
		}
		kind, id, psk = kxKindLink, linkCred[:i], linkPSK(linkCred[i+1:])
	case authToken != "":
		kind, psk = kxKindOwner, ownerPSK(authToken)
	default:
		return nil, errors.New("для E2E нужен мастер-ключ (-password) или ссылка (-link/-cred)")
	}
	return tc.clientKxWith(ctx, kind, id, psk)
}

// clientKxWith — рукопожатие с заданными видом, id ссылки и PSK.
func (tc *tunnelClient) clientKxWith(ctx context.Context, kind byte, id string, psk []byte) (*clientSession, error) {
	curve := ecdh.X25519()
	cPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var nc [nonceBytes]byte
	rand.Read(nc[:])
	head := append([]byte{kxVer, kind, byte(len(id))}, id...)
	k := k0(psk, nc)
	var enc []byte
	if deviceID != "" {
		enc = k.Seal(nil, nonceFor(0), []byte(deviceID), head)
	}
	msg := append([]byte{}, head...)
	msg = append(msg, cPriv.PublicKey().Bytes()...)
	msg = append(msg, nc[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(clientNow().Unix()))
	msg = append(msg, ts[:]...)
	var el [2]byte
	binary.BigEndian.PutUint16(el[:], uint16(len(enc)))
	msg = append(msg, el[:]...)
	msg = append(msg, enc...)
	mac := kxMAC(psk, kxClientPrefix, msg)
	full := append(append([]byte{}, msg...), mac...)

	resp, err := tc.doKx(ctx, full)
	if err != nil {
		return nil, fmt.Errorf("сервер недоступен (%v)", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusForbidden:
		pt, err := k.Open(nil, nonceFor(1), body, mac)
		if err != nil {
			return nil, errKx
		}
		return nil, kxDeny{string(pt)}
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%w (статус %d): нет E2E на сервере или неверный ключ/ссылка", errKx, resp.StatusCode)
	}
	if len(body) != x25519Len+nonceBytes+sidBytes+macLen {
		return nil, errKx
	}
	sEph, ns, sidRaw := body[:x25519Len], body[x25519Len:x25519Len+nonceBytes], body[x25519Len+nonceBytes:x25519Len+nonceBytes+sidBytes]
	sBody := body[:x25519Len+nonceBytes+sidBytes]
	th := sha256.Sum256(append(append([]byte{}, full...), sBody...))
	if subtle.ConstantTimeCompare(body[len(sBody):], kxMAC(psk, kxServerPrefix, th[:])) != 1 {
		return nil, fmt.Errorf("%w: сервер не доказал знание ключа", errKx)
	}
	sPub, err := curve.NewPublicKey(sEph)
	if err != nil {
		return nil, errKx
	}
	dh, err := cPriv.ECDH(sPub)
	if err != nil {
		return nil, errKx
	}
	prk := hkdfExtract(append(nc[:], ns...), append(append([]byte{}, dh...), psk...))
	return &clientSession{
		sid: hex.EncodeToString(sidRaw),
		c2s: hkdfExpand(prk, "c2s|"+string(th[:]), 32),
		s2c: hkdfExpand(prk, "s2c|"+string(th[:]), 32),
	}, nil
}

// doKx шлёт сообщение рукопожатия тем же методом, что и остальной трафик.
func (tc *tunnelClient) doKx(ctx context.Context, msg []byte) (*http.Response, error) {
	return tc.doReqH(ctx, tc.pool[0], "/hello", nil, qToken, msg, map[string]string{kxHeader: fmt.Sprint(kxVer)})
}

// drop удаляет сессию (клиент попрощался).
func (ss *sessionStore) drop(sid string) {
	ss.mu.Lock()
	delete(ss.m, sid)
	ss.mu.Unlock()
}

// ---------------------------------------------------------------- клиент: данные

// streamKeysFor — подключи стрима (nil в старом режиме).
func (tc *tunnelClient) streamKeysFor(id string) *streamKeys {
	if v, ok := tc.keys.Load(id); ok {
		return v.(*streamKeys)
	}
	return nil
}

// wrapUp оборачивает исходящий поток стрим-режима в зашифрованные записи.
func (tc *tunnelClient) wrapUp(id string, r io.Reader) io.Reader {
	if k := tc.streamKeysFor(id); k != nil {
		return newSealReader(r, k.ups, "ups|"+id)
	}
	return r
}

// wrapDown оборачивает входящий поток вниз в расшифровку записей.
func (tc *tunnelClient) wrapDown(id string, r io.Reader) io.Reader {
	if k := tc.streamKeysFor(id); k != nil {
		return newOpenReader(r, k.down, "dn|"+id)
	}
	return r
}
