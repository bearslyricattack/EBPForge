package service

//
//import (
//	"context"
//	"github.com/bearslyricattack/EBPForge/internal/compiler"
//	"github.com/bearslyricattack/EBPForge/internal/loader"
//	pb "github.com/bearslyricattack/EBPForge/proto"
//)
//
//// EbpfLoaderService implements the EbpfLoader gRPC service
//type EbpfLoaderService struct {
//	pb.UnimplementedEbpfLoaderServer
//	compiler *compiler.Compiler
//	loader   *loader.Loader
//}
//
//// NewEbpfLoaderService creates a new service instance with the given dependencies
//func NewEbpfLoaderService(compiler *compiler.Compiler, loader *loader.Loader) *EbpfLoaderService {
//	return &EbpfLoaderService{
//		compiler: compiler,
//		loader:   loader,
//	}
//}
//
//// Load implements the Load RPC method
//func (s *EbpfLoaderService) Load(ctx context.Context, req *pb.LoadRequest) (*pb.LoadResponse, error) {
//	// Compile the C source code
//	objFile, err := s.compiler.Compile(req.SourceCode)
//	if err != nil {
//		return &pb.LoadResponse{
//			Success: false,
//			Error:   err.Error(),
//			Message: "Compilation failed",
//		}, nil
//	}
//
//	// Load the compiled object file
//	programID, err := s.loader.LoadBPF(objFile)
//	if err != nil {
//		return &pb.LoadResponse{
//			Success: false,
//			Error:   err.Error(),
//			Message: "Loading failed",
//		}, nil
//	}
//
//	return &pb.LoadResponse{
//		Success:   true,
//		Message:   "Successfully compiled and loaded eBPF program",
//		ProgramId: programID,
//	}, nil
//}
