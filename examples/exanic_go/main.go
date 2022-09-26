//go:build linux

package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/frozenpine/pkt4go/exanic"
)

var (
	source = "exanic0:0"
)

func init() {
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	flag.StringVar(&source, "src", source, "Capture device")
}

func handler(src, dst net.Addr, payload []byte) (int, error) {
	log.Println(src, dst, payload)

	return len(payload), nil
}

func main() {
	device, err := exanic.CreateHandler(source)

	if err != nil {
		log.Fatal(err)
	}

	ctx, _ := signal.NotifyContext(
		context.Background(),
		os.Interrupt, os.Kill,
	)

	if err = exanic.StartCapture(ctx, device, "", handler); err != nil {
		log.Fatal(err)
	}
}
