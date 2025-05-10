package compiler

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Compile 编译指定路径下的 eBPF 源文件
// path: 源文件所在目录
// name: 源文件名（不含扩展名）
// 返回：编译后的对象文件路径或错误
func Compile(path string, name string) (string, error) {
	// 确保文件名格式正确
	baseName := strings.TrimSuffix(name, ".c")
	baseName = strings.TrimSuffix(baseName, ".bpf")

	srcFile := filepath.Join(path, baseName+".c")
	objFile := filepath.Join(path, baseName+".o")

	// 检查源文件是否存在
	if _, err := os.Stat(srcFile); os.IsNotExist(err) {
		// 尝试 .bpf.c 扩展名
		srcFile = filepath.Join(path, baseName+".bpf.c")
		if _, err := os.Stat(srcFile); os.IsNotExist(err) {
			return "", fmt.Errorf("源文件不存在: %s.c 或 %s.bpf.c", baseName, baseName)
		}
	}

	// 获取系统架构
	arch, err := getSystemArch()
	if err != nil {
		return "", err
	}

	// 构建编译命令
	cmd := buildCompileCommand(srcFile, objFile, arch)

	// 执行编译
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("编译失败: %v\n%s", err, output)
	}

	return objFile, nil
}

// CompileFromCode 从代码字符串编译 eBPF 程序
// code: eBPF 程序代码
// filename: 文件名（可选扩展名）
// 返回：编译后的对象文件路径和可能的错误
func CompileFromCode(code string, filename string) (string, error) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "ebpf-compile-")
	if err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}

	// 处理文件名
	baseName := filepath.Base(filename)
	baseName = strings.TrimSuffix(baseName, filepath.Ext(baseName))

	// 创建源文件
	srcFile := filepath.Join(tempDir, baseName+".c")
	if err := os.WriteFile(srcFile, []byte(code), 0644); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("写入源文件失败: %w", err)
	}

	// 编译
	objFile, err := Compile(tempDir, baseName)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}

	// 返回对象文件路径，调用者负责清理临时目录
	return objFile, nil
}

// CleanupTempFile 清理编译过程中创建的临时文件
func CleanupTempFile(objPath string) error {
	if objPath == "" {
		return nil
	}
	return os.RemoveAll(filepath.Dir(objPath))
}

// getSystemArch 获取系统架构
func getSystemArch() (string, error) {
	cmd := exec.Command("uname", "-m")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("获取系统架构失败: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// buildCompileCommand 构建编译命令
func buildCompileCommand(srcFile, objFile, arch string) *exec.Cmd {
	// 确定架构相关的设置
	archIncludePath := fmt.Sprintf("/usr/include/%s-linux-gnu", arch)
	fmt.Println(archIncludePath)
	archDefine := fmt.Sprintf("__TARGET_ARCH_%s", getArchDefine(arch))
	fmt.Println(archDefine)
	// 获取内核头文件路径
	kernelHeaders := getKernelHeaders()
	fmt.Println(kernelHeaders)
	// 构建编译命令
	args := []string{
		"-g",             // 包含调试信息
		"-O2",            // 优化级别 2
		"-Wall",          // 启用所有警告
		"-target", "bpf", // 目标为 BPF
		"-c", srcFile, // 输入源文件
		"-o", objFile, // 输出对象文件
		"-I", "/usr/include/$(uname -m)-linux-gnu", // 架构特定头文件
	}
	return exec.Command("clang", args...)
}

// getArchDefine 将 uname -m 输出转换为对应的架构定义
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

// getKernelHeaders 获取内核头文件路径
func getKernelHeaders() []string {
	// 获取当前内核版本
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		// 如果获取失败，返回默认路径
		return []string{"/usr/include"}
	}
	kernelVersion := strings.TrimSpace(string(output))
	// 常见的内核头文件位置
	return []string{
		"/usr/include",
		fmt.Sprintf("/usr/src/linux-headers-%s/include", kernelVersion),
		fmt.Sprintf("/usr/src/linux-headers-%s/arch/x86/include", kernelVersion),
		"/usr/include/linux",
	}
}
