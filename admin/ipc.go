package admin

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func (app *App) ipcHandleCmd(w io.Writer, line string) error {
	toks := strings.Split(line, " ")
	if len(toks) != 2 {
		_, err := fmt.Fprintln(w, "error: failed to parse command")
		return err
	}
	switch toks[0] {
	case "login-url":
		url, err := app.IssueLoginURL(strings.TrimRight(toks[1], "\n"))
		if err != nil {
			_, err := fmt.Fprintf(w, "error: failed to issue login url: %s\n", err)
			return err
		}
		_, err = fmt.Fprintf(w, "ok: %s\n", url)
		return err
	case "revoke-refresh-tokens":
		err := app.RevokeRefreshTokens(strings.TrimRight(toks[1], "\n"))
		if err != nil {
			_, err := fmt.Fprintf(w, "error: failed to revoke refresh tokens: %s\n", err)
			return err
		}
		_, err = fmt.Fprint(w, "ok:\n")
		return err
	default:
		_, err := fmt.Fprintln(w, "error: unknown command")
		return err
	}
}

const socketDirectory = "/tmp/tanlweb"

func listenIPCSocket(socketName string) (net.Listener, error) {
	if err := os.MkdirAll(socketDirectory, 0o700); err != nil {
		return nil, err
	}

	socketPath := fmt.Sprintf("%s/%s.sock", socketDirectory, socketName)
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, err
	}

	oldUmask := unix.Umask(0o077)
	defer unix.Umask(oldUmask)
	listener, err := net.ListenUnix("unix", addr)
	if err == nil {
		return listener, nil
	}

	// Test socket, if not in use cleanup and try again.
	if _, err := net.Dial("unix", socketPath); err == nil {
		return nil, errors.New("unix socket in use")
	}
	if err := os.Remove(socketPath); err != nil {
		return nil, err
	}
	return net.ListenUnix("unix", addr)
}

// WARN: Sets umask to 077 while creating socket.
func (app *App) ServeIPC() error {
	listener, err := listenIPCSocket(app.cfg.IPCSocketName)
	if err != nil {
		return err
	}
	log.Printf("Admin service IPC is listening %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection on IPC socket: %s", err)
			continue
		}

		for {
			rd := bufio.NewReader(conn)
			line, err := rd.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				log.Printf("Error reading IPC socket: %s", err)
				break
			}
			if err := app.ipcHandleCmd(conn, line); err != nil {
				log.Printf("Failed to respond to IPC command: %s", err)
				break
			}
			if errors.Is(err, io.EOF) {
				break
			}

		}

		if err := conn.Close(); err != nil {
			log.Printf("Failed to close IPC conn: %s", err)
		}
	}
}
