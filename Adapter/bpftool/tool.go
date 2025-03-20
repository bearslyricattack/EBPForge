package bpftool

import (
	"fmt"
	"os/exec"
)

// ReadMapUsingTool reads the BPF map using bpftool.
func ReadMapUsingTool() (string, error) {
	cmd := exec.Command("bpftool", "map", "dump", "pinned", "/sys/fs/bpf/sys_execve/proc_execve")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute bpftool: %v, output: %s", err, output)
	}
	return string(output), nil
}
