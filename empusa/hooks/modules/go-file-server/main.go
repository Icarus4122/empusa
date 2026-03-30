package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

/*
 * go-file-server - HTTP File Server
 *
 * Drop-in replacement for `python3 -m http.server` that cross-compiles
 * to a single static binary. Useful when Python isn't available on target.
 *
 * Compile:
 *   go build -o fileserver main.go
 *
 * Usage:
 *   ./fileserver -p 8080 -d /path/to/serve
 *
 * Cross-compile for Windows:
 *   GOOS=windows GOARCH=amd64 go build -o fileserver.exe main.go
 */

func main() {
	port := flag.Int("p", 8000, "Port to listen on")
	dir := flag.String("d", ".", "Directory to serve")
	flag.Parse()

	if _, err := os.Stat(*dir); os.IsNotExist(err) {
		log.Fatalf("Directory does not exist: %s", *dir)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	fmt.Printf("[*] Serving %s on http://%s\n", *dir, addr)
	log.Fatal(http.ListenAndServe(addr, http.FileServer(http.Dir(*dir))))
}
