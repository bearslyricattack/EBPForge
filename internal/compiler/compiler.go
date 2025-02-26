package compiler

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
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

// Compile compiles C source code to BPF object file
func (c *Compiler) Compile(sourceCode string) (string, error) {
	// Create temporary directory for compilation
	tempDir, err := ioutil.TempDir(c.TempDir, "ebpf-compile-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write source code to file
	srcFile := filepath.Join(tempDir, "program.c")
	if err := ioutil.WriteFile(srcFile, []byte(sourceCode), 0644); err != nil {
		return "", fmt.Errorf("failed to write source file: %v", err)
	}

	// Output object file
	objFile := filepath.Join(tempDir, "program.o")

	// Compile with clang
	cmd := exec.Command(
		"clang",
		"-g",             // Include debug information
		"-O2",            // Optimization level 2
		"-target", "bpf", // Target BPF
		"-c",          // Compile only, don't link
		srcFile,       // Input source file
		"-o", objFile, // Output object file
		"-I", "/usr/include", // Include standard headers
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compilation failed: %v: %s", err, output)
	}

	// Read compiled object file
	compiledObj, err := ioutil.ReadFile(objFile)
	if err != nil {
		return "", fmt.Errorf("failed to read compiled object file: %v", err)
	}

	// Create directory to store the object file
	persistDir, err := ioutil.TempDir(c.TempDir, "ebpf-obj-")
	if err != nil {
		return "", fmt.Errorf("failed to create persist directory: %v", err)
	}

	// Save the object file to a more persistent location
	persistObjFile := filepath.Join(persistDir, "program.o")
	if err := ioutil.WriteFile(persistObjFile, compiledObj, 0644); err != nil {
		return "", fmt.Errorf("failed to write persistent object file: %v", err)
	}

	return persistObjFile, nil
}
