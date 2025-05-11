package decode

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func ParseBpftoolMapOutput(output string) map[string]uint64 {
	fmt.Println("开始解析 JSON 格式输出...")
	result := make(map[string]uint64)

	// 尝试解析完整的JSON数组
	var entries []struct {
		Key   string      `json:"key"`
		Value json.Number `json:"value"`
	}

	// 确保输入是有效的JSON数组
	if !strings.HasPrefix(strings.TrimSpace(output), "[") {
		output = "[" + output
	}
	if !strings.HasSuffix(strings.TrimSpace(output), "]") {
		output = output + "]"
	}

	err := json.Unmarshal([]byte(output), &entries)
	if err != nil {
		fmt.Printf("JSON解析失败: %v\n", err)
		fmt.Println("尝试逐行解析...")

		// 如果完整解析失败，尝试逐行解析
		scanner := bufio.NewScanner(strings.NewReader(output))
		var currentKey string
		lineCount := 0

		for scanner.Scan() {
			lineCount++
			line := strings.TrimSpace(scanner.Text())
			fmt.Printf("处理第 %d 行: %s\n", lineCount, line)

			// 解析键
			if strings.Contains(line, "\"key\":") {
				keyParts := strings.Split(line, ":")
				if len(keyParts) >= 2 {
					keyStr := strings.TrimSpace(keyParts[1])
					// 移除引号和逗号
					keyStr = strings.Trim(keyStr, "\",")
					currentKey = keyStr
					fmt.Printf("找到键: %q\n", currentKey)
				}
			}

			// 解析值
			if strings.Contains(line, "\"value\":") && currentKey != "" {
				valueParts := strings.Split(line, ":")
				if len(valueParts) >= 2 {
					valueStr := strings.TrimSpace(valueParts[1])
					// 移除逗号
					valueStr = strings.TrimRight(valueStr, ",")
					value, err := strconv.ParseUint(valueStr, 10, 64)
					if err != nil {
						fmt.Printf("解析值失败: %v\n", err)
						continue
					}
					result[currentKey] = value
					fmt.Printf("添加键值对: %q => %d\n", currentKey, value)
					currentKey = ""
				}
			}
		}
	} else {
		// 成功解析完整JSON
		fmt.Printf("成功解析JSON，找到 %d 个条目\n", len(entries))
		for _, entry := range entries {
			value, err := entry.Value.Int64()
			if err != nil {
				fmt.Printf("解析值失败: %v\n", err)
				continue
			}
			result[entry.Key] = uint64(value)
			fmt.Printf("添加键值对: %q => %d\n", entry.Key, value)
		}
	}

	fmt.Printf("解析完成，共得到 %d 个键值对\n", len(result))
	return result
}
