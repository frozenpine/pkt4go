package pcap_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/frozenpine/pkt4go"
	"github.com/frozenpine/pkt4go/pcap"
)

func TestCaptureFile(t *testing.T) {
	source := "file://offer_ens2f1_20221017.pcap"
	filter := "tcp and host 172.16.33.69"

	handler, err := pcap.CreateHandler(source)
	if err != nil {
		t.Fatal(err)
	}

	dataHandler := func(src, dst net.Addr, ts time.Time, data []byte) (int, error) {
		t.Logf("%s %s -> %s: %d", ts, src, dst, len(data))
		return len(data), nil
	}

	pkt4go.TCPDataMode = pkt4go.TCPRawData

	if err := pcap.StartCapture(context.TODO(), handler, filter, dataHandler); err != nil {
		t.Fatal(err)
	}
}
