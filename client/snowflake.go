// Client transport plugin for the Snowflake pluggable transport.
package main

import (
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/keroserene/go-webrtc"
)

const (
	ReconnectTimeout         = 10
	DefaultSnowflakeCapacity = 1
	SnowflakeTimeout         = 30
)

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

// Maintain |SnowflakeCapacity| number of available WebRTC connections, to
// transfer to the Tor SOCKS handler when needed.
func ConnectLoop(snowflakes SnowflakeCollector) {
	for {
		// Check if ending is necessary.
		_, err := snowflakes.Collect()
		if nil != err {
			log.Println("WebRTC:", err,
				" Retrying in", ReconnectTimeout, "seconds...")
		}
		select {
		case <-time.After(time.Second * ReconnectTimeout):
			continue
		case <-snowflakes.Melted():
			log.Println("ConnectLoop: stopped.")
			return
		}
	}
}

// Accept local SOCKS connections and pass them to the handler.
func socksAcceptLoop(ln *pt.SocksListener, snowflakes SnowflakeCollector) error {
	defer ln.Close()
	log.Println("Started SOCKS listener.")
	for {
		log.Println("SOCKS listening...")
		conn, err := ln.AcceptSocks()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return err
		}
		log.Println("SOCKS accepted: ", conn.Req)
		err = handler(conn, snowflakes)
		if err != nil {
			log.Printf("handler error: %s", err)
		}
	}
}

// Given an accepted SOCKS connection, establish a WebRTC connection to the
// remote peer and exchange traffic.
func handler(socks SocksConnector, snowflakes SnowflakeCollector) error {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()
	// Obtain an available WebRTC remote. May block.
	snowflake := snowflakes.Pop()
	if nil == snowflake {
		socks.Reject()
		return errors.New("handler: Received invalid Snowflake")
	}
	defer socks.Close()
	defer snowflake.Close()
	log.Println("---- Handler: snowflake assigned ----")
	err := socks.Grant(&net.TCPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}

	go func() {
		// When WebRTC resets, close the SOCKS connection too.
		snowflake.WaitForReset()
		socks.Close()
	}()

	// Begin exchanging data. Either WebRTC or localhost SOCKS will close first.
	// In eithercase, this closes the handler and induces a new handler.
	copyLoop(socks, snowflake)
	log.Println("---- Handler: closed ---")
	return nil
}

// Exchanges bytes between two ReadWriters.
// (In this case, between a SOCKS and WebRTC connection.)
func copyLoop(a, b io.ReadWriter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(b, a)
		wg.Done()
	}()
	go func() {
		io.Copy(a, b)
		wg.Done()
	}()
	wg.Wait()
	log.Println("copy loop ended")
}

func main() {
	iceServersCommas := flag.String("ice", "", "comma-separated list of ICE servers")
	brokerURL := flag.String("url", "", "URL of signaling broker")
	frontDomain := flag.String("front", "", "front domain")
	codec := flag.String("codec", "post", "codec to connect to the broker (\"post\")")
	logFilename := flag.String("log", "", "name of log file")
	logToStateDir := flag.Bool("logToStateDir", false, "resolve the log file relative to tor's pt state dir")
	max := flag.Int("max", DefaultSnowflakeCapacity,
		"capacity for number of multiplexed WebRTC peers")
	flag.Parse()

	webrtc.SetLoggingVerbosity(1)
	log.SetFlags(log.LstdFlags | log.LUTC)

	if *logFilename != "" {
		if *logToStateDir {
			stateDir, err := pt.MakeStateDir()
			if err != nil {
				log.Fatal(err)
			}
			*logFilename = filepath.Join(stateDir, *logFilename)
		}
		logFile, err := os.OpenFile(*logFilename,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	log.Println("\n\n\n --- Starting Snowflake Client ---")

	var iceServers IceServerList
	if len(strings.TrimSpace(*iceServersCommas)) > 0 {
		option := webrtc.OptionIceServer(*iceServersCommas)
		iceServers = append(iceServers, option)
	}

	// Prepare to collect remote WebRTC peers.
	snowflakes := NewPeers(*max)
	if "" != *brokerURL {
		// Use potentially domain-fronting broker to rendezvous.
		switch *codec {
		case "post":
			broker := NewBrokerChannel(*brokerURL, *frontDomain, *codec, CreateBrokerTransport())
			snowflakes.Tongue = NewWebRTCDialer(broker, iceServers)
		default:
			log.Fatal("Unsupported codec.")
		}
	} else {
		// Otherwise, use manual copy and pasting of SDP messages.
		snowflakes.Tongue = NewCopyPasteDialer(iceServers)
	}
	if nil == snowflakes.Tongue {
		log.Fatal("Unable to prepare rendezvous method.")
		return
	}
	// Use a real logger to periodically output how much traffic is happening.
	snowflakes.BytesLogger = &BytesSyncLogger{
		inboundChan: make(chan int, 5), outboundChan: make(chan int, 5),
		inbound: 0, outbound: 0, inEvents: 0, outEvents: 0,
	}
	go snowflakes.BytesLogger.Log()

	go ConnectLoop(snowflakes)

	// Begin goptlib client process.
	ptInfo, err := pt.ClientSetup(nil)
	if err != nil {
		log.Fatal(err)
	}
	if ptInfo.ProxyURL != nil {
		pt.ProxyError("proxy is not supported")
		os.Exit(1)
	}
	listeners := make([]net.Listener, 0)
	for _, methodName := range ptInfo.MethodNames {
		switch methodName {
		case "snowflake":
			// TODO: Be able to recover when SOCKS dies.
			ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
			if err != nil {
				pt.CmethodError(methodName, err.Error())
				break
			}
			go socksAcceptLoop(ln, snowflakes)
			pt.Cmethod(methodName, ln.Version(), ln.Addr())
			listeners = append(listeners, ln)
		default:
			pt.CmethodError(methodName, "no such method")
		}
	}
	pt.CmethodsDone()

	var numHandlers int = 0
	var sig os.Signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			io.Copy(ioutil.Discard, os.Stdin)
			log.Printf("synthesizing SIGTERM because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	// keep track of handlers and wait for a signal
	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}

	// signal received, shut down
	for _, ln := range listeners {
		ln.Close()
	}
	snowflakes.End()
	for numHandlers > 0 {
		numHandlers += <-handlerChan
	}
	log.Println("snowflake is done.")
}
