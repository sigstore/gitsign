// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: cache.proto

package cache_go_proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type StoreCredentialRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id         string      `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Credential *Credential `protobuf:"bytes,2,opt,name=credential,proto3" json:"credential,omitempty"`
}

func (x *StoreCredentialRequest) Reset() {
	*x = StoreCredentialRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cache_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoreCredentialRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreCredentialRequest) ProtoMessage() {}

func (x *StoreCredentialRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cache_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreCredentialRequest.ProtoReflect.Descriptor instead.
func (*StoreCredentialRequest) Descriptor() ([]byte, []int) {
	return file_cache_proto_rawDescGZIP(), []int{0}
}

func (x *StoreCredentialRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *StoreCredentialRequest) GetCredential() *Credential {
	if x != nil {
		return x.Credential
	}
	return nil
}

type StoreCredentialResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StoreCredentialResponse) Reset() {
	*x = StoreCredentialResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cache_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoreCredentialResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreCredentialResponse) ProtoMessage() {}

func (x *StoreCredentialResponse) ProtoReflect() protoreflect.Message {
	mi := &file_cache_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreCredentialResponse.ProtoReflect.Descriptor instead.
func (*StoreCredentialResponse) Descriptor() ([]byte, []int) {
	return file_cache_proto_rawDescGZIP(), []int{1}
}

type GetCredentialRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetCredentialRequest) Reset() {
	*x = GetCredentialRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cache_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCredentialRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCredentialRequest) ProtoMessage() {}

func (x *GetCredentialRequest) ProtoReflect() protoreflect.Message {
	mi := &file_cache_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCredentialRequest.ProtoReflect.Descriptor instead.
func (*GetCredentialRequest) Descriptor() ([]byte, []int) {
	return file_cache_proto_rawDescGZIP(), []int{2}
}

func (x *GetCredentialRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type Credential struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PrivateKey []byte `protobuf:"bytes,1,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	CertPem    []byte `protobuf:"bytes,2,opt,name=cert_pem,json=certPem,proto3" json:"cert_pem,omitempty"`
	CertChain  []byte `protobuf:"bytes,3,opt,name=cert_chain,json=certChain,proto3" json:"cert_chain,omitempty"`
}

func (x *Credential) Reset() {
	*x = Credential{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cache_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Credential) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Credential) ProtoMessage() {}

func (x *Credential) ProtoReflect() protoreflect.Message {
	mi := &file_cache_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Credential.ProtoReflect.Descriptor instead.
func (*Credential) Descriptor() ([]byte, []int) {
	return file_cache_proto_rawDescGZIP(), []int{3}
}

func (x *Credential) GetPrivateKey() []byte {
	if x != nil {
		return x.PrivateKey
	}
	return nil
}

func (x *Credential) GetCertPem() []byte {
	if x != nil {
		return x.CertPem
	}
	return nil
}

func (x *Credential) GetCertChain() []byte {
	if x != nil {
		return x.CertChain
	}
	return nil
}

var File_cache_proto protoreflect.FileDescriptor

var file_cache_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x73,
	0x69, 0x67, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x67, 0x69, 0x74, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63,
	0x61, 0x63, 0x68, 0x65, 0x22, 0x6b, 0x0a, 0x16, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x72, 0x65,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x41,
	0x0a, 0x0a, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x21, 0x2e, 0x73, 0x69, 0x67, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x67, 0x69, 0x74,
	0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x43, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x0a, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61,
	0x6c, 0x22, 0x19, 0x0a, 0x17, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x26, 0x0a, 0x14,
	0x47, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x64, 0x22, 0x67, 0x0a, 0x0a, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x61, 0x6c, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x5f, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
	0x4b, 0x65, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x70, 0x65, 0x6d, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x63, 0x65, 0x72, 0x74, 0x50, 0x65, 0x6d, 0x12, 0x1d,
	0x0a, 0x0a, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x09, 0x63, 0x65, 0x72, 0x74, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x32, 0xe8, 0x01,
	0x0a, 0x0f, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x53, 0x74, 0x6f, 0x72,
	0x65, 0x12, 0x72, 0x0a, 0x0f, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x61, 0x6c, 0x12, 0x2d, 0x2e, 0x73, 0x69, 0x67, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x67,
	0x69, 0x74, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x53, 0x74, 0x6f,
	0x72, 0x65, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x2e, 0x2e, 0x73, 0x69, 0x67, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x67, 0x69,
	0x74, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x53, 0x74, 0x6f, 0x72,
	0x65, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x61, 0x0a, 0x0d, 0x47, 0x65, 0x74, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x12, 0x2b, 0x2e, 0x73, 0x69, 0x67, 0x74, 0x6f, 0x72, 0x65,
	0x2e, 0x67, 0x69, 0x74, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x47,
	0x65, 0x74, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x73, 0x69, 0x67, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x67, 0x69,
	0x74, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x22, 0x00, 0x42, 0x3b, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x69, 0x67, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f,
	0x67, 0x69, 0x74, 0x73, 0x69, 0x67, 0x6e, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
	0x2f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2f, 0x63, 0x61, 0x63, 0x68, 0x65, 0x5f, 0x67, 0x6f, 0x5f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_cache_proto_rawDescOnce sync.Once
	file_cache_proto_rawDescData = file_cache_proto_rawDesc
)

func file_cache_proto_rawDescGZIP() []byte {
	file_cache_proto_rawDescOnce.Do(func() {
		file_cache_proto_rawDescData = protoimpl.X.CompressGZIP(file_cache_proto_rawDescData)
	})
	return file_cache_proto_rawDescData
}

var file_cache_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_cache_proto_goTypes = []interface{}{
	(*StoreCredentialRequest)(nil),  // 0: sigtore.gitsign.cache.StoreCredentialRequest
	(*StoreCredentialResponse)(nil), // 1: sigtore.gitsign.cache.StoreCredentialResponse
	(*GetCredentialRequest)(nil),    // 2: sigtore.gitsign.cache.GetCredentialRequest
	(*Credential)(nil),              // 3: sigtore.gitsign.cache.Credential
}
var file_cache_proto_depIdxs = []int32{
	3, // 0: sigtore.gitsign.cache.StoreCredentialRequest.credential:type_name -> sigtore.gitsign.cache.Credential
	0, // 1: sigtore.gitsign.cache.CredentialStore.StoreCredential:input_type -> sigtore.gitsign.cache.StoreCredentialRequest
	2, // 2: sigtore.gitsign.cache.CredentialStore.GetCredential:input_type -> sigtore.gitsign.cache.GetCredentialRequest
	1, // 3: sigtore.gitsign.cache.CredentialStore.StoreCredential:output_type -> sigtore.gitsign.cache.StoreCredentialResponse
	3, // 4: sigtore.gitsign.cache.CredentialStore.GetCredential:output_type -> sigtore.gitsign.cache.Credential
	3, // [3:5] is the sub-list for method output_type
	1, // [1:3] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_cache_proto_init() }
func file_cache_proto_init() {
	if File_cache_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cache_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoreCredentialRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_cache_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoreCredentialResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_cache_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCredentialRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_cache_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Credential); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cache_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_cache_proto_goTypes,
		DependencyIndexes: file_cache_proto_depIdxs,
		MessageInfos:      file_cache_proto_msgTypes,
	}.Build()
	File_cache_proto = out.File
	file_cache_proto_rawDesc = nil
	file_cache_proto_goTypes = nil
	file_cache_proto_depIdxs = nil
}
