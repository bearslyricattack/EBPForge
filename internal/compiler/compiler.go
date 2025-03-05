package compiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Compiler handles compilation of eBPF C source code
type Compiler struct {
	TempDir string
}

// NewCompiler creates a new compiler instance
func NewCompiler() *Compiler {
	return &Compiler{
		TempDir: os.TempDir(),
	}
}

func (c *Compiler) Compile(path string, name string) (string, error) {

	fmt.Printf("%s\n", path)
	fmt.Printf("%s\n", name)
	// 构造源文件和目标文件路径
	srcFile := filepath.Join(path, name+".c")
	objFile := filepath.Join(path, name+".o")

	// 获取系统架构
	archCmd := exec.Command("uname", "-m")
	archBytes, err := archCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to determine system architecture: %v", err)
	}
	arch := strings.TrimSpace(string(archBytes))

	// 构建特定架构的头文件路径
	archIncludePath := fmt.Sprintf("/usr/include/%s-linux-gnu", arch)

	// Compile with clang
	cmd := exec.Command(
		"clang",
		"-g",             // Include debug information
		"-O2",            // Optimization level 2
		"-Wall",          // Enable all warnings
		"-target", "bpf", // Target BPF
		"-c",          // Compile only, don't link
		srcFile,       // Input source file
		"-o", objFile, // Output object file
		"-I", archIncludePath, // 添加特定架构的头文件路径
		"-D", "__TARGET_ARCH_x86", // 定义目标架构
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compilation failed: %v: %s", err, output)
	}

	// 直接返回目标文件路径
	return objFile, nil
}
