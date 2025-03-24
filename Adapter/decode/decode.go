package decode

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const maxCommLen = 16

// EbpfEvent Go 结构体，必须与 eBPF 结构体一致
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

// 调用 bpftool 获取 perf 数据并解析
func getPerfData(filePath string) ([]string, error) {
	// 执行 bpftool 命令来获取 perf 数据
	cmd := exec.Command("bpftool", "perf", "dump", filePath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	// 执行命令
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute bpftool: %v", err)
	}

	// 将输出按行分割
	lines := strings.Split(out.String(), "\n")
	return lines, nil
}

// 解析 bpftool 输出为 eBPF 事件数据
func parseEventFromLine(line string) (EbpfEvent, error) {
	var event EbpfEvent

	// 将行数据按空格分割
	parts := strings.Fields(line)
	if len(parts) < 10 {
		return event, fmt.Errorf("invalid data format: %s", line)
	}

	// 将分割后的数据转换为对应类型
	timestamp, _ := strconv.ParseUint(parts[0], 10, 64)
	pid, _ := strconv.ParseUint(parts[1], 10, 32)
	tid, _ := strconv.ParseUint(parts[2], 10, 32)
	uid, _ := strconv.ParseUint(parts[3], 10, 32)
	gid, _ := strconv.ParseUint(parts[4], 10, 32)
	eventType, _ := strconv.ParseUint(parts[5], 10, 32)
	data1, _ := strconv.ParseUint(parts[6], 10, 64)
	data2, _ := strconv.ParseUint(parts[7], 10, 64)
	data3, _ := strconv.ParseUint(parts[8], 10, 64)

	// 填充结构体
	event.Timestamp = timestamp
	event.PID = uint32(pid)
	event.TID = uint32(tid)
	event.UID = uint32(uid)
	event.GID = uint32(gid)
	event.EventType = uint32(eventType)
	event.Data1 = data1
	event.Data2 = data2
	event.Data3 = data3

	// 处理命令字段 (假设在数据中有命令字段)
	copy(event.Command[:], parts[9])

	return event, nil
}

// 读取并解析 perf 数据
func readPerfData(filePath string) {
	// 获取 bpftool 输出
	lines, err := getPerfData(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting perf data: %v\n", err)
		return
	}

	// 解析每一行的数据
	for _, line := range lines {
		if line == "" {
			continue
		}

		// 解析事件
		event, err := parseEventFromLine(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing event: %v\n", err)
			continue
		}

		// 打印事件
		fmt.Println(event)
	}
}

// 将数据转换为可读格式
func (e EbpfEvent) String() string {
	return fmt.Sprintf("[%s] PID=%d TID=%d UID=%d GID=%d Type=%d Cmd=%s Data1=%d Data2=%d Data3=%d",
		time.Unix(0, int64(e.Timestamp)).Format("2006-01-02 15:04:05"),
		e.PID, e.TID, e.UID, e.GID, e.EventType,
		string(e.Command[:]), e.Data1, e.Data2, e.Data3)
}
