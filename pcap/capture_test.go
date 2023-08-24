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
	filter := "tcp and port 44926"

	handler, err := pcap.CreateHandler(source)
	if err != nil {
		t.Fatal(err)
	}

	count := 0

	dataHandler := func(session *core.Session, ts time.Time, data []byte) (int, error) {
		count += 1

		var used int

		if count%2 == 0 {
			used = len(data)
		} else {
			used = len(data) / 2
		}

		t.Logf("%s %s: %d, %d", ts, session, len(data), used)

		return used, nil
	}

	if err := pcap.StartCapture(context.TODO(), handler, filter, dataHandler); err != nil {
		t.Fatal(err)
	}
}
