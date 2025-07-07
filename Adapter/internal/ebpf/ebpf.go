package ebpf

import (
	"errors"
	"sync"
)

type EBPFProgram struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Type       string `json:"type"`
	Promehteus string `json:"promehteus"`
}

var (
	ebpfPrograms = make(map[string]EBPFProgram) // 初始化
	lock         = sync.RWMutex{}
)

func AddProgram(name string, path string, programType string) error {
	lock.Lock()
	defer lock.Unlock()
	if _, exists := ebpfPrograms[name]; exists {
		return errors.New("program already exists: " + name)
	}
	var program = EBPFProgram{
		Name: name,
		Path: path,
		Type: programType,
	}
	ebpfPrograms[name] = program
	return nil
}

func GetProgram(name string) (EBPFProgram, bool) {
	lock.RLock()
	defer lock.RUnlock()
	program, ok := ebpfPrograms[name]
	return program, ok
}

func ListPrograms() []EBPFProgram {
	lock.RLock()
	defer lock.RUnlock()
	var list []EBPFProgram
	for _, p := range ebpfPrograms {
		list = append(list, p)
	}
	return list
}

func RemoveProgram(name string) {
	lock.Lock()
	defer lock.Unlock()
	delete(ebpfPrograms, name)
}
