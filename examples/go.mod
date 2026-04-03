module github.com/elazarl/goproxy/examples/goproxy-transparent

go 1.25.0

require (
	github.com/coder/websocket v1.8.14
	github.com/elazarl/goproxy v1.5.0
	github.com/elazarl/goproxy/ext v0.0.0-20250117123040-e9229c451ab8
	github.com/inconshreveable/go-vhost v1.0.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)

replace github.com/elazarl/goproxy => ../
