package main

// Надёжность транспорта: возобновляемая доставка вниз после обрыва долгого
// GET (буферизующие/с таймаутом CDN рвут его регулярно), ретраи вверх с тем
// же seq (сервер их и так принимает идемпотентно — см. handleUp), и
// полу-закрытие: когда приложение закончило слать вверх, сервер закрывает
// запись в цель, не обрывая при этом обратное чтение ответа.
//
// Полноценный мультиплекс многих логических стримов в одной сессии (вместо
// отдельного X25519-рукопожатия на каждый SOCKS-коннект) в этот проход не
// вошёл — это отдельная, более крупная переделка формата кадров поверх
// стрима, а не улучшение поверх текущего. Здесь — только надёжность.

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Настраиваемые лимиты надёжности (var, а не const — тесты уменьшают их,
// чтобы проверять редкие ветки вроде вытеснения из кольца, не гоняя мегабайты
// данных по-настоящему).
var (
	// maxDownRingBytes — сколько последних байт вниз сервер держит в памяти
	// на стрим ради возобновления после обрыва. Компромисс: больше — длиннее
	// обрыв, который можно пережить без потери данных; но это память на
	// каждый одновременный стрим.
	maxDownRingBytes = 4 << 20

	maxDownReconnects = 8 // сколько раз клиент переподключает down прежде чем сдаться
	maxUpRetries      = 4 // сколько раз клиент повторяет один и тот же chunk вверх
)

const (
	// downTruncatedTrailer — HTTP-трейлер: сервер эвиктнул часть данных уже
	// ПОСЛЕ того, как отправил 200 (редкий путь — клиент сильно отстал).
	// Статус к этому моменту не поменять, поэтому сигналим трейлером: иначе
	// клиент видел бы чистый io.EOF и принял обрыв за штатный конец потока.
	downTruncatedTrailer = "X-Cdn-Truncated"
)

// dnRing — буфер последних отправленных вниз байт с абсолютными смещениями.
// Позволяет клиенту после обрыва GET попросить "/t/down?from=<offset>" и
// получить то, что он не успел дочитать, не начиная стрим заново. Каждый
// append — уже финальные байты на проводе (например, зашифрованная запись
// целиком с её 4-байтовым префиксом длины), а не исходные данные цели: так
// resume не требует ничего перешифровывать и не путает счётчики nonce.
type dnRing struct {
	mu      sync.Mutex
	base    uint64 // абсолютное смещение первого байта в buf
	buf     []byte
	closed  bool
	waiters []chan struct{}
}

func (r *dnRing) append(b []byte) {
	if len(b) == 0 {
		return
	}
	r.mu.Lock()
	r.buf = append(r.buf, b...)
	if excess := len(r.buf) - maxDownRingBytes; excess > 0 {
		r.buf = r.buf[excess:]
		r.base += uint64(excess)
	}
	ws := r.waiters
	r.waiters = nil
	r.mu.Unlock()
	for _, w := range ws {
		close(w)
	}
}

func (r *dnRing) closeRing() {
	r.mu.Lock()
	r.closed = true
	ws := r.waiters
	r.waiters = nil
	r.mu.Unlock()
	for _, w := range ws {
		close(w)
	}
}

// tail — текущий конец буфера: с чего начинать, если клиент не просил resume.
func (r *dnRing) tail() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.base + uint64(len(r.buf))
}

// poll возвращает всё, что накопилось начиная с pos. Если там пока пусто и
// поток жив — отдаёт канал wait, который закроется при новых данных, закрытии
// или добавлении данных гонки не будет: регистрация ожидающего и проверка
// делаются под одной блокировкой, что и append/closeRing.
func (r *dnRing) poll(pos uint64) (data []byte, end uint64, gone, closed bool, wait <-chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	end = r.base + uint64(len(r.buf))
	if pos < r.base {
		return nil, end, true, false, nil
	}
	if end > pos {
		return append([]byte(nil), r.buf[pos-r.base:]...), end, false, false, nil
	}
	if r.closed {
		return nil, end, false, true, nil
	}
	ch := make(chan struct{})
	r.waiters = append(r.waiters, ch)
	return nil, end, false, false, ch
}

// halfCloseTarget закрывает запись в целевое соединение (TCP FIN на запись),
// не трогая чтение — origin увидит конец запроса и сможет ответить, а стрим
// продолжит получать вниз то, что тот пришлёт. Не все net.Conn это умеют
// (например, TLS-обёртки без CloseWrite) — тогда просто не делаем ничего:
// это не хуже прежнего поведения (полный конец придёт по /t/close или idle).
func (s *stream) halfCloseTarget() {
	if cw, ok := s.conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}

// ---------------------------------------------------------------- клиент

var errLocalClosed = errors.New("локальный сокет закрыт")

// copyDown копирует src (ответ сервера, возможно уже расшифрованный) в conn
// (локальное приложение), различая, где случилась ошибка: если сорвалась
// ЗАПИСЬ в conn — переподключаться нет смысла, локальный сокет мёртв.
func copyDown(conn net.Conn, src io.Reader) (uint64, error) {
	var n uint64
	buf := make([]byte, 32*1024)
	for {
		rn, rerr := src.Read(buf)
		if rn > 0 {
			if _, werr := conn.Write(buf[:rn]); werr != nil {
				return n, errLocalClosed
			}
			n += uint64(rn)
			st.down.Add(uint64(rn))
		}
		if rerr != nil {
			if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
	}
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
