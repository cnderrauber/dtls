package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/pion/transport/v2/udp"
	"golang.org/x/net/ipv4"
)

var (
	listenPort    = flag.Int("l", 0, "listen port")
	batch         = flag.Bool("b", true, "batch mode")
	batchSize     = flag.Int("bs", 256, "batch size")
	batchInterval = flag.Duration("bi", 5*time.Millisecond, "batch interval")
	connectHost   = flag.String("c", "localhost:9091", "connect host")
	duration      = flag.Duration("d", 1*time.Minute, "duration")
	pktSize       = flag.Int("ps", 1400, "packet size")
	concurrency   = flag.Int("cc", 1, "concurrency")
	dtlsMode      = flag.Bool("tls", false, "dtls mode")
	reverseRW     = flag.Bool("rw", false, "reverse read/write, if it is false, server will read and client write")
	connectedMode = flag.Bool("cm", false, "connected mode")

	packet int64
	bytes  int64

	totalPacket int64
	totalBytes  int64
)

func main() {
	flag.Parse()

	if *listenPort > 0 {
		server()
	} else {
		client()
	}
}

func server() {
	lc := udp.ListenConfig{
		Batch: udp.BatchIOConfig{
			Enable:             *batch,
			ReadBatchSize:      *batchSize,
			WriteBatchSize:     *batchSize,
			WriteBatchInterval: *batchInterval,
		},
		ForkSocket:           *connectedMode,
		DelayForkSocketBatch: true,
	}
	if *dtlsMode {
		lc.AcceptFilter = func(packet []byte) bool {
			pkts, err := recordlayer.UnpackDatagram(packet)
			if err != nil || len(pkts) < 1 {
				return false
			}
			h := &recordlayer.Header{}
			if err := h.Unmarshal(pkts[0]); err != nil {
				return false
			}
			return h.ContentType == protocol.ContentTypeHandshake
		}
	}

	laddr := net.UDPAddr{Port: *listenPort}
	listener, err := lc.Listen("udp", &laddr)
	if err != nil {
		panic(err)
	}

	if *dtlsMode {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dtlsListener, err := dtls.NewListener(listener, &dtls.Config{
			PSK: func(hint []byte) ([]byte, error) {
				fmt.Printf("Client's hint: %s \n", hint)
				return []byte{0xAB, 0xC1, 0x23}, nil
			},
			PSKIdentityHint:      []byte("Pion DTLS Client"),
			CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
			// Create timeout context for accepted connection.
			ConnectContextMaker: func() (context.Context, func()) {
				return context.WithTimeout(ctx, 30*time.Second)
			},
		})
		if err != nil {
			panic(err)
		}

		listener = dtlsListener
	}

	// time.AfterFunc(*duration, func() {
	// 	listener.Close()
	// })

	go report()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("accept error:", err)
			break
		}
		fmt.Println("connected, raddr: ", conn.RemoteAddr(), "err", err)
		go func(conn net.Conn) {
			defer conn.Close()
			if *reverseRW {
				writeConn(conn)
			} else {
				readConn(conn)
			}

		}(conn)
	}
}

func client() {
	go report()
	for i := 0; i < *concurrency; i++ {
		go func() {
			raddr, err := net.ResolveUDPAddr("udp", *connectHost)
			if err != nil {
				panic(err)
			}

			var conn net.Conn

			if *dtlsMode {
				config := &dtls.Config{
					PSK: func(hint []byte) ([]byte, error) {
						fmt.Printf("Server's hint: %s \n", hint)
						return []byte{0xAB, 0xC1, 0x23}, nil
					},
					PSKIdentityHint:      []byte("Pion DTLS Server"),
					CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
					ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
				}

				// Connect to a DTLS server
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				conn, err = dtls.DialWithContext(ctx, "udp", raddr, config)
			} else {
				conn, err = net.DialUDP("udp", nil, raddr)
			}
			if err != nil {
				panic(err)
			}

			if *reverseRW {
				readConn(conn)
			} else {
				if *batch {
					writeBatch(conn.(*net.UDPConn))
				} else {
					writeConn(conn)
				}
			}
		}()
	}

	time.Sleep(*duration)
	os.Exit(0)
}

func readConn(conn net.Conn) {
	buf := make([]byte, *pktSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}

		atomic.AddInt64(&packet, 1)
		atomic.AddInt64(&bytes, int64(n))

		atomic.AddInt64(&totalPacket, 1)
		atomic.AddInt64(&totalBytes, int64(n))
	}
}

func writeConn(conn net.Conn) {
	buf := make([]byte, *pktSize)
	for {
		n, err := conn.Write(buf)
		if err != nil {
			if err == io.ErrClosedPipe {
				break
			}
			panic(err)
		}

		atomic.AddInt64(&packet, 1)
		atomic.AddInt64(&bytes, int64(n))

		atomic.AddInt64(&totalPacket, 1)
		atomic.AddInt64(&totalBytes, int64(n))
	}
}

func writeBatch(conn net.PacketConn) {
	pktConn := ipv4.NewPacketConn(conn)
	msgs := make([]ipv4.Message, *batchSize)
	for i := 0; i < *batchSize; i++ {
		msgs[i].Buffers = [][]byte{make([]byte, *pktSize)}
	}

	for {
		n, err := pktConn.WriteBatch(msgs, 0)
		if err != nil {
			if err == io.ErrClosedPipe {
				break
			}
			panic(err)
		}
		atomic.AddInt64(&packet, int64(n))
		atomic.AddInt64(&bytes, int64(n*(*pktSize)))

		atomic.AddInt64(&totalPacket, int64(n))
		atomic.AddInt64(&totalBytes, int64(n*(*pktSize)))
	}
}

func report() {
	start := time.Now()
	lastReport := start
	tk := time.NewTicker(5 * time.Second)
	for {
		<-tk.C
		lastElapsed := time.Since(lastReport)
		kpps := float64(packet) / lastElapsed.Seconds() / 1000
		mbps := float64(bytes) * 8 / lastElapsed.Seconds() / 1e6
		lastReport = time.Now()
		atomic.StoreInt64(&packet, 0)
		atomic.StoreInt64(&bytes, 0)

		elapsed := time.Since(start)
		totalkPps := float64(totalPacket) / elapsed.Seconds() / 1000
		totalMbps := float64(totalBytes) * 8 / elapsed.Seconds() / 1e6
		fmt.Printf("elapsed: %d s, kpps: %.2f, mbps: %.2f, total kpps: %.2f, total mbps: %.2f \n", int(elapsed.Seconds()), kpps, mbps, totalkPps, totalMbps)
	}
}
