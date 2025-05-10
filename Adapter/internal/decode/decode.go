package decode

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
)

func ParseBpftoolMapOutput(output string) map[string]uint64 {
	result := make(map[string]uint64)
	scanner := bufio.NewScanner(strings.NewReader(output))
	var key string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "key:") {
			hexPart := strings.TrimSpace(strings.TrimPrefix(line, "key:"))
			keyBytes, err := hex.DecodeString(strings.ReplaceAll(hexPart, " ", ""))
			if err != nil {
				continue
			}
			key = string(bytes.TrimRight(keyBytes, "\x00")) // 去除多余 \x00
		}

		if strings.HasPrefix(line, "value:") && key != "" {
			hexVal := strings.TrimSpace(strings.TrimPrefix(line, "value:"))
			val, err := strconv.ParseUint(strings.TrimPrefix(hexVal, "0x"), 16, 64)
			if err != nil {
				continue
			}
			result[key] = val
			key = ""
		}
	}
	return result
}
