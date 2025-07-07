package pkg

// AttachType defines the type of eBPF program attachment
type AttachType string

// AttachArgs contains parameters for eBPF program attachment
type AttachArgs struct {
	Name     string // Program name
	Ebpftype string // Attachment type
	Target   string // Attachment target
	Code     string // Program code
	Program  string // Program section name
}
