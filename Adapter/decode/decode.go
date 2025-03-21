package decode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"os"
	"time"
)

const maxCommLen = 16

// Go 结构体，必须与 eBPF 结构体一致
type EbpfEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	UID       uint32
	GID       uint32
	EventType uint32
	Data1     uint64
	Data2     uint64
	Data3     uint64
	Command   [maxCommLen]byte
}

// 解析 eBPF 事件数据
func parseEvent(record perf.Record) EbpfEvent {
	var event EbpfEvent
	buf := bytes.NewBuffer(record.RawSample)
	err := binary.Read(buf, binary.LittleEndian, &event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode eBPF event: %v\n", err)
	}
	return event
}

// 将数据转换为可读格式
func (e EbpfEvent) String() string {
	return fmt.Sprintf("[%s] PID=%d TID=%d UID=%d GID=%d Type=%d Cmd=%s Data1=%d Data2=%d Data3=%d",
		time.Unix(0, int64(e.Timestamp)).Format("2006-01-02 15:04:05"),
		e.PID, e.TID, e.UID, e.GID, e.EventType,
		string(e.Command[:]), e.Data1, e.Data2, e.Data3)
}
