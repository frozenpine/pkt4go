package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/frozenpine/pkt4go/core"
	"github.com/frozenpine/pkt4go/socket"
)

var (
	multiAddr = ""
	bind      = ""
	maxSize   = 30

	// lastGuavaTick guava.MarketData
)

func init() {
	flag.StringVar(&multiAddr, "multi", multiAddr, "Multicast group for listening.")
	flag.StringVar(&bind, "bind", bind, "Interface name/IP for receive data.")
	flag.IntVar(&maxSize, "out", maxSize, "Byte array output length.")

	log.SetFlags(log.Flags() | log.Lmicroseconds)
}

func decoder(session *core.Session, ts time.Time, data []byte) (int, error) {
	var size = len(data)
	var postFix = ""

	if size > maxSize {
		size = maxSize
		postFix = "..."
	}

	log.Printf("%s [%4d]bytes: [%X%s]\n", session, size, data[:size], postFix)

	return size, nil
}

func main() {
	if !flag.Parsed() {
		flag.Parse()
	}

	if bind == "" {
		log.Fatalln("Binding interface must be specified.")
	}

	if err := socket.ServeMultiCast(context.TODO(), multiAddr, bind, 1024*1024, decoder); err != nil {
		log.Fatal(err)
	}
}
