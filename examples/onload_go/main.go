//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/frozenpine/pkt4go/onload"
)

var (
	iface       = ""
	dryRun      = false
	showVersion = false
)

func init() {
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	flag.StringVar(&iface, "iface", "", "Interface name.")
	flag.BoolVar(&dryRun, "dry", false, "Dry run without real capture.")
	flag.BoolVar(&showVersion, "ver", false, "Get exanic version.")

	flag.Parse()
}

func handler(src, dst net.Addr, ts time.Time, payload []byte) (int, error) {
	switch dst.Network() {
	case "tcp":
		log.Printf("[TCP] %s %s -> %s: payload %d bytes", ts, src, dst, len(payload))
	case "udp":
		log.Printf("[UDP] %s %s -> %s: payload %d bytes", ts, src, dst, len(payload))
	default:
		log.Printf("%s %s -> %s: payload %d bytes", ts, src, dst, len(payload))
	}

	return len(payload), nil
}

func main() {
	var (
		device *onload.Device
		err    error
	)

	if !flag.Parsed() {
		flag.Parse()
	}

	if showVersion {
		fmt.Println(onload.GetVersion(), onload.GetInterfaceVersion())
		return
	}

	if iface == "" {
		log.Fatalln("interface can not be empty.")
	}

	if device, err = onload.CreateHandler(iface); err != nil {
		log.Fatalf("create handler failed: %v", err)
	}

	if dryRun {
		return
	}

	ctx, _ := signal.NotifyContext(
		context.Background(),
		os.Interrupt, os.Kill,
	)

	if err = onload.StartCapture(ctx, device, "", handler); err != nil {
		log.Fatal(err)
	}
}
