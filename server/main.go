package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cacggghp/vk-turn-proxy/tcputil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/xtaci/smux"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	vlessMode := flag.Bool("vless", false, "VLESS mode: forward TCP connections (for VLESS) instead of UDP packets")
	aggregate := flag.Bool("aggregate", false, "Aggregate N DTLS streams per client into a single backend UDP socket. "+
		"When enabled, each DTLS stream MUST send a 16-byte session ID immediately after the handshake. "+
		"Replies from the backend are round-robined across the streams that share the ID. "+
		"WIRE-INCOMPATIBLE with non-aggregating clients — turn this on only when every client speaks the protocol.")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}
	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Connect to a DTLS server
	listener, err := dtls.ListenWithOptions(
		"udp",
		addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
	)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		if err = listener.Close(); err != nil {
			panic(err)
		}
	})

	if *aggregate {
		fmt.Println("Listening (aggregate mode)")
	} else {
		fmt.Println("Listening")
	}

	var sessions *sessionManager
	if *aggregate {
		sessions = newSessionManager()
	}

	wg1 := sync.WaitGroup{}
	for {
		select {
		case <-ctx.Done():
			wg1.Wait()
			return
		default:
		}
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		wg1.Add(1)
		go func(conn net.Conn) {
			defer wg1.Done()
			defer func() {
				if closeErr := conn.Close(); closeErr != nil {
					log.Printf("failed to close incoming connection: %s", closeErr)
				}
			}()
			log.Printf("Connection from %s\n", conn.RemoteAddr())

			// Perform the handshake with a 30-second timeout
			ctx1, cancel1 := context.WithTimeout(ctx, 30*time.Second)
			defer cancel1()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				log.Println("Type error: expected *dtls.Conn")
				return
			}
			log.Println("Start handshake")
			if err := dtlsConn.HandshakeContext(ctx1); err != nil {
				log.Printf("Handshake failed: %v", err)
				return
			}
			log.Println("Handshake done")

			switch {
			case *vlessMode:
				handleVLESSConnection(ctx, dtlsConn, *connect)
			case *aggregate:
				handleAggregatedUDPConnection(ctx, conn, *connect, sessions)
			default:
				handleUDPConnection(ctx, conn, *connect)
			}

			log.Printf("Connection closed: %s\n", conn.RemoteAddr())
		}(conn)
	}
}

// ---------- session aggregation (port of kiper292/vk-turn-proxy) ----------

// userSession owns one UDP socket to the backend (e.g. wg-quick@wg0) and a
// list of DTLS connections that share it. Upstream packets from every DTLS
// stream flow into the single backendConn; downstream packets from
// backendConn are round-robined across the DTLS streams. WireGuard's own
// replay window absorbs the resulting reordering.
type userSession struct {
	id          string
	backendConn net.Conn
	manager     *sessionManager
	ctx         context.Context
	cancel      context.CancelFunc

	lock     sync.RWMutex
	conns    []net.Conn
	lastUsed uint32 // atomic counter for round-robin downstream selection
}

type sessionManager struct {
	lock     sync.Mutex
	sessions map[string]*userSession
}

func newSessionManager() *sessionManager {
	return &sessionManager{sessions: make(map[string]*userSession)}
}

func (m *sessionManager) getOrCreate(ctx context.Context, id, connectAddr string) (*userSession, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if s, ok := m.sessions[id]; ok {
		return s, nil
	}
	backend, err := net.Dial("udp", connectAddr)
	if err != nil {
		return nil, err
	}
	sessCtx, cancel := context.WithCancel(ctx)
	s := &userSession{
		id:          id,
		backendConn: backend,
		manager:     m,
		ctx:         sessCtx,
		cancel:      cancel,
	}
	m.sessions[id] = s
	go s.backendReaderLoop()
	return s, nil
}

func (s *userSession) addConn(c net.Conn) {
	s.lock.Lock()
	s.conns = append(s.conns, c)
	s.lock.Unlock()
}

func (s *userSession) removeConn(c net.Conn) {
	s.lock.Lock()
	for i, x := range s.conns {
		if x == c {
			s.conns = append(s.conns[:i], s.conns[i+1:]...)
			break
		}
	}
	s.lock.Unlock()
}

// backendReaderLoop reads packets from the shared backend UDP socket and
// dispatches each one to ONE of the currently-attached DTLS conns. The
// 5-minute deadline doubles as an idle-session reaper: when no client
// stream has written anything in 5 minutes, the read errors out and the
// session is torn down.
func (s *userSession) backendReaderLoop() {
	defer s.cleanup()
	buf := make([]byte, 1600)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		if err := s.backendConn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			log.Printf("session %s backend SetReadDeadline: %v", s.id, err)
			return
		}
		n, err := s.backendConn.Read(buf)
		if err != nil {
			log.Printf("session %s backend read: %v", s.id, err)
			return
		}

		s.lock.RLock()
		if len(s.conns) == 0 {
			s.lock.RUnlock()
			continue
		}
		idx := atomic.AddUint32(&s.lastUsed, 1) % uint32(len(s.conns))
		target := s.conns[idx]
		s.lock.RUnlock()

		if err := target.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			log.Printf("session %s DTLS SetWriteDeadline: %v", s.id, err)
			continue
		}
		if _, err := target.Write(buf[:n]); err != nil {
			log.Printf("session %s DTLS write: %v", s.id, err)
			// the per-stream goroutine that owns `target` will hit its own
			// read error next and call removeConn, so we just skip here.
		}
	}
}

func (s *userSession) cleanup() {
	s.cancel()
	_ = s.backendConn.Close()

	s.manager.lock.Lock()
	delete(s.manager.sessions, s.id)
	s.manager.lock.Unlock()

	s.lock.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.lock.Unlock()
}

// handleAggregatedUDPConnection handles one DTLS stream within an aggregate
// session. The first 16 bytes after the handshake are the session ID; all
// subsequent reads are forwarded to the session's shared backend socket.
func handleAggregatedUDPConnection(ctx context.Context, conn net.Conn, connectAddr string, sm *sessionManager) {
	idBuf := make([]byte, 16)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("aggregate: SetReadDeadline for session id: %v", err)
		return
	}
	if _, err := io.ReadFull(conn, idBuf); err != nil {
		log.Printf("aggregate: read session id: %v", err)
		return
	}
	sessionID := fmt.Sprintf("%x", idBuf)

	session, err := sm.getOrCreate(ctx, sessionID, connectAddr)
	if err != nil {
		log.Printf("aggregate: getOrCreate session %s: %v", sessionID, err)
		return
	}
	session.addConn(conn)
	defer session.removeConn(conn)

	log.Printf("aggregate: stream attached to session %s from %s", sessionID, conn.RemoteAddr())

	buf := make([]byte, 1600)
	for {
		select {
		case <-session.ctx.Done():
			return
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Minute)); err != nil {
			log.Printf("aggregate: session %s SetReadDeadline: %v", sessionID, err)
			return
		}
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("aggregate: session %s stream read: %v", sessionID, err)
			return
		}

		// Drop the turnbridge keepalive sentinel (4 bytes of 0xFF) — same
		// reasoning as in handleUDPConnection.
		if n == 4 && buf[0] == 0xFF && buf[1] == 0xFF && buf[2] == 0xFF && buf[3] == 0xFF {
			continue
		}

		if err := session.backendConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			log.Printf("aggregate: session %s backend SetWriteDeadline: %v", sessionID, err)
			return
		}
		if _, err := session.backendConn.Write(buf[:n]); err != nil {
			log.Printf("aggregate: session %s backend write: %v", sessionID, err)
			return
		}
	}
}

// handleUDPConnection forwards DTLS packets to a UDP backend (WireGuard).
func handleUDPConnection(ctx context.Context, conn net.Conn, connectAddr string) {
	serverConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer func() {
		if err = serverConn.Close(); err != nil {
			log.Printf("failed to close outgoing connection: %s", err)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	ctx2, cancel2 := context.WithCancel(ctx)
	context.AfterFunc(ctx2, func() {
		if err := conn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set incoming deadline: %s", err)
		}
		if err := serverConn.SetDeadline(time.Now()); err != nil {
			log.Printf("failed to set outgoing deadline: %s", err)
		}
	})
	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err1 := conn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := conn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			// App-level keepalive sentinel from turnbridge client:
			// exactly 4 bytes of 0xFF. WireGuard transport_data is min 32
			// bytes and its first byte is one of 0x01..0x04, so this
			// sentinel can never collide with a real WG packet. We drop
			// it silently so wg-quick@wg0 isn't bothered with junk.
			if n == 4 && buf[0] == 0xFF && buf[1] == 0xFF && buf[2] == 0xFF && buf[3] == 0xFF {
				continue
			}

			if err1 = serverConn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = serverConn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer cancel2()
		buf := make([]byte, 1600)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			if err1 := serverConn.SetReadDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			n, err1 := serverConn.Read(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			if err1 = conn.SetWriteDeadline(time.Now().Add(time.Minute * 30)); err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			_, err1 = conn.Write(buf[:n])
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
		}
	}()
	wg.Wait()
}

// handleVLESSConnection creates a KCP+smux session over DTLS and forwards
// each smux stream as a TCP connection to the backend (Xray/VLESS).
func handleVLESSConnection(ctx context.Context, dtlsConn net.Conn, connectAddr string) {
	// 1. Create KCP session over DTLS
	kcpSess, err := tcputil.NewKCPOverDTLS(dtlsConn, true)
	if err != nil {
		log.Printf("KCP session error: %s", err)
		return
	}
	defer func() {
		if err := kcpSess.Close(); err != nil {
			log.Printf("failed to close KCP session: %v", err)
		}
	}()
	log.Printf("KCP session established (server)")

	// 2. Create smux server session over KCP
	smuxSess, err := smux.Server(kcpSess, tcputil.DefaultSmuxConfig())
	if err != nil {
		log.Printf("smux server error: %s", err)
		return
	}
	defer func() {
		if err := smuxSess.Close(); err != nil {
			log.Printf("failed to close smux session: %v", err)
		}
	}()
	log.Printf("smux session established (server)")

	// 3. Accept smux streams and forward to backend via TCP
	var wg sync.WaitGroup
	for {
		stream, err := smuxSess.AcceptStream()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				log.Printf("smux accept error: %s", err)
			}
			break
		}

		wg.Add(1)
		go func(s *smux.Stream) {
			defer wg.Done()

			defer func() {
				if err := s.Close(); err != nil && err != smux.ErrGoAway {
					log.Printf("failed to close smux stream: %v", err)
				}
			}()

			// Connect to backend (Xray/VLESS)
			backendConn, err := net.DialTimeout("tcp", connectAddr, 10*time.Second)
			if err != nil {
				log.Printf("backend dial error: %s", err)
				return
			}
			defer func() {
				if err := backendConn.Close(); err != nil {
					log.Printf("failed to close backend connection: %v", err)
				}
			}()

			// Bidirectional copy
			pipeConn(ctx, s, backendConn)
		}(stream)
	}
	wg.Wait()
}

// pipeConn copies data bidirectionally between two connections.
func pipeConn(ctx context.Context, c1, c2 net.Conn) {
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	context.AfterFunc(ctx2, func() {
		if err := c1.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c1: %v", err)
		}
		if err := c2.SetDeadline(time.Now()); err != nil {
			log.Printf("pipeConn: failed to set deadline c2: %v", err)
		}
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c1, c2); err != nil {
			log.Printf("pipeConn: c1<-c2 copy error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(c2, c1); err != nil {
			log.Printf("pipeConn: c2<-c1 copy error: %v", err)
		}
	}()

	wg.Wait()

	// Reset deadlines
	_ = c1.SetDeadline(time.Time{})
	_ = c2.SetDeadline(time.Time{})
}
