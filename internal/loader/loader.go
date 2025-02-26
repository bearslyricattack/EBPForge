package loader

import (
	"fmt"
	"github.com/cilium/ebpf"
)

// Loader handles loading of eBPF programs
type Loader struct {
	loadedPrograms map[string]*ebpf.Program
}

// NewLoader creates a new loader instance
func NewLoader() *Loader {
	return &Loader{
		loadedPrograms: make(map[string]*ebpf.Program),
	}
}

// LoadBPF loads a compiled BPF program from an object file
func (l *Loader) LoadBPF(objectPath string) (string, error) {
	// Load the compiled object file
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return "", fmt.Errorf("failed to load BPF collection spec: %v", err)
	}

	// Load the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return "", fmt.Errorf("failed to load BPF collection: %v", err)
	}

	// For simplicity, we'll assume there's a main program to attach to a file operation
	// In a real implementation, you'd want to be more specific about which program to load
	var prog *ebpf.Program
	for name, p := range coll.Programs {
		if prog == nil {
			prog = p
		}
		fmt.Printf("Loaded program: %s\n", name)
	}

	if prog == nil {
		coll.Close()
		return "", fmt.Errorf("no programs found in the object file")
	}

	// Generate a unique ID for this program
	programID := fmt.Sprintf("prog_%p", prog)
	l.loadedPrograms[programID] = prog

	// In a real implementation, you would now attach the program to something
	// For example, to attach to a kprobe for file open:
	// kp, err := link.Kprobe("do_sys_open", prog, nil)
	// if err != nil {
	//     return "", fmt.Errorf("failed to create kprobe: %v", err)
	// }

	return programID, nil
}

// UnloadBPF unloads a previously loaded BPF program
func (l *Loader) UnloadBPF(programID string) error {
	prog, exists := l.loadedPrograms[programID]
	if !exists {
		return fmt.Errorf("program with ID %s not found", programID)
	}

	if err := prog.Close(); err != nil {
		return fmt.Errorf("failed to close program: %v", err)
	}

	delete(l.loadedPrograms, programID)
	return nil
}
