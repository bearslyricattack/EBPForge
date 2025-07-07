package compiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Compile compiles an eBPF source file at the specified path
func Compile(path string, name string) (string, error) {
	baseName := strings.TrimSuffix(name, ".c")
	srcFile := filepath.Join(path, baseName+".c")
	objFile := filepath.Join(path, baseName+".o")
	if _, err := os.Stat(srcFile); os.IsNotExist(err) {
		srcFile = filepath.Join(path, baseName+".bpf.c")
		if _, err := os.Stat(srcFile); os.IsNotExist(err) {
			return "", fmt.Errorf("source file does not exist: %s.c or %s.bpf.c", baseName, baseName)
		}
	}
	arch, err := getSystemArch()
	if err != nil {
		return "", err
	}
	cmd := buildCompileCommand(srcFile, objFile, arch)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compilation failed: %v\n%s", err, output)
	}
	return objFile, nil
}

// CompileFromCode compiles eBPF program from a code string
func CompileFromCode(code string, filename string) (string, error) {
	targetDir := "/home/sealos/EBPForge/Program"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return "", fmt.Errorf("failed to ensure target directory exists: %w", err)
	}
	baseName := filepath.Base(filename)
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
	srcFile := filepath.Join(targetDir, baseName+".c")
	if err := os.WriteFile(srcFile, []byte(code), 0644); err != nil {
		return "", fmt.Errorf("failed to write source file: %w", err)
	}
	output, err := Compile(targetDir, baseName)
	if err != nil {
		return "", err
	}
	return output, nil
}

// CompileCode compiles eBPF program using a temporary directory
func CompileCode(code string, filename string) (string, error) {
	tempDir, err := os.MkdirTemp("", "ebpf-compile-")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}
	baseName := filepath.Base(filename)
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))
	srcFile := filepath.Join(tempDir, baseName+".c")
	if err := os.WriteFile(srcFile, []byte(code), 0644); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to write source file: %w", err)
	}
	objFile, err := Compile(tempDir, baseName)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}
	return objFile, nil
}

// CleanupTempFile cleans up temporary files created during compilation
func CleanupTempFile(objPath string) error {
	if objPath == "" {
		return nil
	}
	return os.RemoveAll(filepath.Dir(objPath))
}

func getSystemArch() (string, error) {
	cmd := exec.Command("uname", "-m")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get system architecture: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func buildCompileCommand(srcFile, objFile, arch string) *exec.Cmd {
	archIncludePath := fmt.Sprintf("/usr/include/%s-linux-gnu", arch)
	args := []string{
		"-g",
		"-O2",
		"-Wall",
		"-target", "bpf",
		"-c", srcFile,
		"-o", objFile,
		"-I", archIncludePath,
	}
	return exec.Command("clang", args...)
}

func getArchDefine(arch string) string {
	switch arch {
	case "x86_64":
		return "x86"
	case "aarch64":
		return "arm64"
	case "armv7l":
		return "arm"
	default:
		return arch
	}
}

func getKernelHeaders() []string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return []string{"/usr/include"}
	}
	kernelVersion := strings.TrimSpace(string(output))
	return []string{
		"/usr/include",
		fmt.Sprintf("/usr/src/linux-headers-%s/include", kernelVersion),
		fmt.Sprintf("/usr/src/linux-headers-%s/arch/x86/include", kernelVersion),
		"/usr/include/linux",
	}
}
