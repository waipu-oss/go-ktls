package ktls_test

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"

	ktls "github.com/waipu-oss/go-ktls"
)

// ExampleNewListener serves HTTPS with kernel TLS offload. The listener is a
// drop-in net.Listener; connections that cannot be offloaded fall back to a
// plain *tls.Conn transparently, so enabling it is always safe.
func ExampleNewListener() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	inner, err := net.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}

	ln := ktls.NewListener(inner, &tls.Config{
		Certificates: []tls.Certificate{cert},
		// h2 stays in userspace, so offer only http/1.1 to drive the kTLS path.
		NextProtos: []string{"http/1.1"},
	}, ktls.WithObserver(func(reason string, remoteAddr net.Addr, state tls.ConnectionState, err error) {
		// reason is "offloaded" on success, otherwise a ktls.Reason* bucket.
		if reason != "offloaded" {
			log.Printf("ktls fallback %q from %s: %v", reason, remoteAddr, err)
		}
	}))
	defer ln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Served via sendfile(2) through the kernel TLS socket.
			http.ServeFile(w, r, "/var/www/html"+r.URL.Path)
		}),
	}

	log.Fatal(srv.Serve(ln))
}
