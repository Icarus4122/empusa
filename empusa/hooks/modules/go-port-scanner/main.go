package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

/*
 * go-port-scanner - Concurrent TCP Port Scanner
 *
 * Compile:
 *   go build -o scanner main.go
 *
 * Usage:
 *   ./scanner 10.10.10.10
 *
 * Cross-compile for Windows:
 *   GOOS=windows GOARCH=amd64 go build -o scanner.exe main.go
 */

func scanPort(host string, port int, wg *sync.WaitGroup, results chan<- int) {
	defer wg.Done()
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return
	}
	conn.Close()
	results <- port
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: scanner <host>")
		os.Exit(1)
	}

	host := os.Args[1]
	fmt.Printf("[*] Scanning %s (ports 1-1024)...\n", host)

	var wg sync.WaitGroup
	results := make(chan int, 1024)

	for port := 1; port <= 1024; port++ {
		wg.Add(1)
		go scanPort(host, port, &wg, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var open []int
	for port := range results {
		open = append(open, port)
	}

	sort.Ints(open)
	fmt.Printf("\n[+] Open ports on %s:\n", host)
	for _, p := range open {
		fmt.Printf("    %d/tcp open\n", p)
	}
	fmt.Printf("\n[*] Scan complete. %d open port(s) found.\n", len(open))
}
