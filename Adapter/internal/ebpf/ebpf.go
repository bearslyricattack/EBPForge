package ebpf

import (
	"errors"
	"sync"
)

// EBPFProgram 表示一个 eBPF 程序实例
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

// AddProgram 新增一个 eBPF 程序
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

// GetProgram 获取某个 eBPF 程序
func GetProgram(name string) (EBPFProgram, bool) {
	lock.RLock()
	defer lock.RUnlock()
	program, ok := ebpfPrograms[name]
	return program, ok
}

// ListPrograms 返回所有程序
func ListPrograms() []EBPFProgram {
	lock.RLock()
	defer lock.RUnlock()
	var list []EBPFProgram
	for _, p := range ebpfPrograms {
		list = append(list, p)
	}
	//fmt.Print("当前的程序有：")
	//fmt.Println(list)
	return list
}

// RemoveProgram 删除程序
func RemoveProgram(name string) {
	lock.Lock()
	defer lock.Unlock()
	delete(ebpfPrograms, name)
}
