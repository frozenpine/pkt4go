package pcap_test

import (
	"context"
	"testing"
	"time"

	"github.com/frozenpine/pkt4go/core"
	"github.com/frozenpine/pkt4go/pcap"
)

func TestCaptureFile(t *testing.T) {
	source := "file://4tick-level2-A.20230812.pcap"
	filter := "tcp and net 172.18.32.0/24"

	handler, err := pcap.CreateHandler(source)
	if err != nil {
		t.Fatal(err)
	}

	count := 0

	dataHandler := func(session *core.Session, ts time.Time, data []byte) (int, error) {
		count += 1

		if count%2 == 0 {
			t.Logf("%s %s: %d", ts, session, len(data))
			return len(data), nil
		}

		return len(data) / 2, nil
	}

	if err := pcap.StartCapture(context.TODO(), handler, filter, dataHandler); err != nil {
		t.Fatal(err)
	}
}
