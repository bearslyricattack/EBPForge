// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: proto/ebpf_loader.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	EbpfLoader_Load_FullMethodName = "/ebpfloader.EbpfLoader/Load"
)

// EbpfLoaderClient is the client API for EbpfLoader service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type EbpfLoaderClient interface {
	// Load takes C source code and returns the load result
	Load(ctx context.Context, in *LoadRequest, opts ...grpc.CallOption) (*LoadResponse, error)
}

type ebpfLoaderClient struct {
	cc grpc.ClientConnInterface
}

func NewEbpfLoaderClient(cc grpc.ClientConnInterface) EbpfLoaderClient {
	return &ebpfLoaderClient{cc}
}

func (c *ebpfLoaderClient) Load(ctx context.Context, in *LoadRequest, opts ...grpc.CallOption) (*LoadResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(LoadResponse)
	err := c.cc.Invoke(ctx, EbpfLoader_Load_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EbpfLoaderServer is the server API for EbpfLoader service.
// All implementations must embed UnimplementedEbpfLoaderServer
// for forward compatibility.
type EbpfLoaderServer interface {
	// Load takes C source code and returns the load result
	Load(context.Context, *LoadRequest) (*LoadResponse, error)
	mustEmbedUnimplementedEbpfLoaderServer()
}

// UnimplementedEbpfLoaderServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedEbpfLoaderServer struct{}

func (UnimplementedEbpfLoaderServer) Load(context.Context, *LoadRequest) (*LoadResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Load not implemented")
}
func (UnimplementedEbpfLoaderServer) mustEmbedUnimplementedEbpfLoaderServer() {}
func (UnimplementedEbpfLoaderServer) testEmbeddedByValue()                    {}

// UnsafeEbpfLoaderServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to EbpfLoaderServer will
// result in compilation errors.
type UnsafeEbpfLoaderServer interface {
	mustEmbedUnimplementedEbpfLoaderServer()
}

func RegisterEbpfLoaderServer(s grpc.ServiceRegistrar, srv EbpfLoaderServer) {
	// If the following call pancis, it indicates UnimplementedEbpfLoaderServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&EbpfLoader_ServiceDesc, srv)
}

func _EbpfLoader_Load_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoadRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EbpfLoaderServer).Load(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: EbpfLoader_Load_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EbpfLoaderServer).Load(ctx, req.(*LoadRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// EbpfLoader_ServiceDesc is the grpc.ServiceDesc for EbpfLoader service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var EbpfLoader_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "ebpfloader.EbpfLoader",
	HandlerType: (*EbpfLoaderServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Load",
			Handler:    _EbpfLoader_Load_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/ebpf_loader.proto",
}
