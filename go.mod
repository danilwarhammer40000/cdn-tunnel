module cdntunnel

go 1.22

// Локальная сборка в этом окружении не достаёт до proxy.golang.org/golang.org —
// эти replace смотрят на официальные read-only зеркала Go-команды на GitHub.
// На обычной машине с доступом в интернет их можно убрать: `go mod tidy` сам
// подтянет канонические golang.org/x/* с proxy.golang.org.
replace golang.org/x/crypto => github.com/golang/crypto v0.21.0

replace golang.org/x/net => github.com/golang/net v0.23.0

replace golang.org/x/sys => github.com/golang/sys v0.18.0

replace golang.org/x/text => github.com/golang/text v0.14.0

require (
	github.com/refraction-networking/utls v1.6.7
	golang.org/x/net v0.23.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)
