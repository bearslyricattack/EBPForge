package decode

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func ParseBpftoolMapOutput(output string) map[string]uint64 {
	result := make(map[string]uint64)
	var entries []struct {
		Key   string      `json:"key"`
		Value json.Number `json:"value"`
	}
	// Ensure the input is a valid JSON array
	if !strings.HasPrefix(strings.TrimSpace(output), "[") {
		output = "[" + output
	}
	if !strings.HasSuffix(strings.TrimSpace(output), "]") {
		output = output + "]"
	}
	err := json.Unmarshal([]byte(output), &entries)
	if err != nil {
		// If complete parsing fails, try line-by-line parsing
		result = parseLineByLine(output)
	} else {
		for _, entry := range entries {
			value, err := entry.Value.Int64()
			if err != nil {
				fmt.Printf("Failed to parse value: %v\n", err)
				continue
			}
			result[entry.Key] = uint64(value)
		}
	}
	return result
}

// parseLineByLine parses the output line by line when JSON parsing fails
func parseLineByLine(output string) map[string]uint64 {
	result := make(map[string]uint64)
	scanner := bufio.NewScanner(strings.NewReader(output))
	var currentKey string
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "\"key\":") {
			keyParts := strings.Split(line, ":")
			if len(keyParts) >= 2 {
				keyStr := strings.TrimSpace(keyParts[1])
				keyStr = strings.Trim(keyStr, "\",")
				currentKey = keyStr
			}
		}
		if strings.Contains(line, "\"value\":") && currentKey != "" {
			valueParts := strings.Split(line, ":")
			if len(valueParts) >= 2 {
				valueStr := strings.TrimSpace(valueParts[1])
				valueStr = strings.TrimRight(valueStr, ",")
				value, err := strconv.ParseUint(valueStr, 10, 64)
				if err != nil {
					continue
				}
				result[currentKey] = value
				currentKey = ""
			}
		}
	}

	return result
}
