package bpftool

import (
	"fmt"
	"os/exec"
)

// ReadMapUsingTool reads the BPF map using bpftool.
func ReadMapUsingTool(path string) (string, error) {
	cmd := exec.Command("bpftool", "map", "dump", "pinned", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute bpftool: %v, output: %s", err, output)
	}
	return string(output), nil
}
