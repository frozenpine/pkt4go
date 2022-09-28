package pcap_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/frozenpine/pkt4go/pcap"
)

func TestCaputureTime(t *testing.T) {
	source := "file://../smdp/mdqp_snapshot.pcap"
	filter := "tcp and src host 192.168.11.73 and dst host 172.16.100.44"

	handler, err := pcap.CreateHandler(source)
	if err != nil {
		t.Fatal(err)
	}

	smdpHandler := func(src, dst net.Addr, ts time.Time, data []byte) (int, error) {

		t.Logf("%s %s -> %s: %d", ts, src, dst, len(data))
		return len(data), nil
	}

	ctx, cancle := context.WithCancel(context.Background())

	go func() {
		<-time.After(time.Second)
		cancle()
	}()

	if err := pcap.StartCapture(ctx, handler, filter, smdpHandler); err != nil {
		t.Fatal(err)
	}
}
