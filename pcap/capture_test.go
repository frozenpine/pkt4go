package pcap_test

import (
	"context"
	"testing"
	"time"

	"github.com/frozenpine/pkt4go/core"
	"github.com/frozenpine/pkt4go/pcap"
)

func TestCaptureFile(t *testing.T) {
	source := "file://offer_ens2f1_20221017.pcap"
	filter := "tcp and host 172.16.33.69"

	handler, err := pcap.CreateHandler(source)
	if err != nil {
		t.Fatal(err)
	}

	dataHandler := func(session *core.Session, ts time.Time, data []byte) (int, error) {
		t.Logf("%s %s: %d", ts, session, len(data))
		return len(data), nil
	}

	if err := pcap.StartCapture(context.TODO(), handler, filter, dataHandler); err != nil {
		t.Fatal(err)
	}
}
