package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// cmdSink is a throwaway data-collector endpoint: it accepts run reports the
// way the real collector does (200 OK), counts them and discards them, so a
// load test exercises the report path without filling a real database.
func cmdSink(args []string) error {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	listen := fs.String("listen", ":8099", "listen address")
	_ = fs.Parse(args)

	var reqs, bytes, bad int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			atomic.AddInt64(&bad, 1)
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		n, _ := io.Copy(io.Discard, r.Body)
		atomic.AddInt64(&reqs, 1)
		atomic.AddInt64(&bytes, n)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	})
	go func() {
		var last int64
		for range time.Tick(30 * time.Second) {
			n := atomic.LoadInt64(&reqs)
			log.Printf("sink: %d reports (%.1f/s), %.1f MB, %d rejected",
				n, float64(n-last)/30, float64(atomic.LoadInt64(&bytes))/1e6, atomic.LoadInt64(&bad))
			last = n
		}
	}()
	log.Printf("sink listening on %s", *listen)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}
