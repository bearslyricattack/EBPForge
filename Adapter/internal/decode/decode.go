package decode

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

func ParseBpftoolMapOutput(output string) map[string]uint64 {
	fmt.Println("开始解析 bpftool map 输出...")
	result := make(map[string]uint64)
	scanner := bufio.NewScanner(strings.NewReader(output))
	var key string
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())
		fmt.Printf("处理第 %d 行: %s\n", lineCount, line)

		if strings.HasPrefix(line, "key:") {
			hexPart := strings.TrimSpace(strings.TrimPrefix(line, "key:"))
			fmt.Printf("发现键值行，十六进制部分: %s\n", hexPart)

			keyBytes, err := hex.DecodeString(strings.ReplaceAll(hexPart, " ", ""))
			if err != nil {
				fmt.Printf("解析键值十六进制失败: %v\n", err)
				continue
			}

			key = string(bytes.TrimRight(keyBytes, "\x00")) // 去除多余 \x00
			fmt.Printf("解析后的键名: %q\n", key)
		}

		if strings.HasPrefix(line, "value:") && key != "" {
			hexVal := strings.TrimSpace(strings.TrimPrefix(line, "value:"))
			fmt.Printf("发现值行，十六进制值: %s\n", hexVal)

			val, err := strconv.ParseUint(strings.TrimPrefix(hexVal, "0x"), 16, 64)
			if err != nil {
				fmt.Printf("解析值十六进制失败: %v\n", err)
				continue
			}

			result[key] = val
			fmt.Printf("添加键值对: %q => %d\n", key, val)
			key = ""
		}
	}

	fmt.Printf("解析完成，共解析 %d 行，得到 %d 个键值对\n", lineCount, len(result))
	return result
}
