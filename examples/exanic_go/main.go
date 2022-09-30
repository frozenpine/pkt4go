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

	"github.com/frozenpine/pkt4go/exanic"
)

var (
	source      = ""
	iface       = ""
	dryRun      = false
	showVersion = false
)

func init() {
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	flag.StringVar(&source, "src", "", "Capture device.")
	flag.StringVar(&iface, "iface", "", "Interface name.")
	flag.BoolVar(&dryRun, "dry", false, "Dry run without real capture.")
	flag.BoolVar(&showVersion, "ver", false, "Get exanic version.")

	flag.Parse()
}

func handler(src, dst net.Addr, ts time.Time, payload []byte) (int, error) {
	log.Println(ts, src, dst, payload)

	return len(payload), nil
}

func main() {
	var (
		device *exanic.Device
		err    error
	)

	if !flag.Parsed() {
		flag.Parse()
	}

	if showVersion {
		fmt.Println(exanic.GetVersion())
		return
	}

	if source != "" {
		device, err = exanic.CreateHandler(source)
	} else if iface != "" {
		device, err = exanic.GetHandlerByIfaceName(iface)
	} else {
		log.Fatalln("no device or iface specified.")
	}

	if err != nil {
		log.Fatal(err)
	}

	if dryRun {
		return
	}

	ctx, _ := signal.NotifyContext(
		context.Background(),
		os.Interrupt, os.Kill,
	)

	if err = exanic.StartCapture(ctx, device, "", handler); err != nil {
		log.Fatal(err)
	}
}
