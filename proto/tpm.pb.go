// Code generated by protoc-gen-go. DO NOT EDIT.
// source: tpm.proto

package proto

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// Enum values come from TCG Algorithm Registry - v1.27 - Table 3
type ObjectType int32

const (
	ObjectType_OBJECT_INVALID ObjectType = 0
	ObjectType_RSA            ObjectType = 1
	ObjectType_ECC            ObjectType = 35
)

var ObjectType_name = map[int32]string{
	0:  "OBJECT_INVALID",
	1:  "RSA",
	35: "ECC",
}

var ObjectType_value = map[string]int32{
	"OBJECT_INVALID": 0,
	"RSA":            1,
	"ECC":            35,
}

func (x ObjectType) String() string {
	return proto.EnumName(ObjectType_name, int32(x))
}

func (ObjectType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{0}
}

type HashAlgo int32

const (
	HashAlgo_HASH_INVALID HashAlgo = 0
	HashAlgo_SHA1         HashAlgo = 4
	HashAlgo_SHA256       HashAlgo = 11
)

var HashAlgo_name = map[int32]string{
	0:  "HASH_INVALID",
	4:  "SHA1",
	11: "SHA256",
}

var HashAlgo_value = map[string]int32{
	"HASH_INVALID": 0,
	"SHA1":         4,
	"SHA256":       11,
}

func (x HashAlgo) String() string {
	return proto.EnumName(HashAlgo_name, int32(x))
}

func (HashAlgo) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{1}
}

type Ticket struct {
	Type                 uint32   `protobuf:"varint,12,opt,name=type,proto3" json:"type,omitempty"`
	Hierarchy            uint32   `protobuf:"varint,11,opt,name=hierarchy,proto3" json:"hierarchy,omitempty"`
	Digest               []byte   `protobuf:"bytes,10,opt,name=digest,proto3" json:"digest,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Ticket) Reset()         { *m = Ticket{} }
func (m *Ticket) String() string { return proto.CompactTextString(m) }
func (*Ticket) ProtoMessage()    {}
func (*Ticket) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{0}
}

func (m *Ticket) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Ticket.Unmarshal(m, b)
}
func (m *Ticket) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Ticket.Marshal(b, m, deterministic)
}
func (m *Ticket) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Ticket.Merge(m, src)
}
func (m *Ticket) XXX_Size() int {
	return xxx_messageInfo_Ticket.Size(m)
}
func (m *Ticket) XXX_DiscardUnknown() {
	xxx_messageInfo_Ticket.DiscardUnknown(m)
}

var xxx_messageInfo_Ticket proto.InternalMessageInfo

func (m *Ticket) GetType() uint32 {
	if m != nil {
		return m.Type
	}
	return 0
}

func (m *Ticket) GetHierarchy() uint32 {
	if m != nil {
		return m.Hierarchy
	}
	return 0
}

func (m *Ticket) GetDigest() []byte {
	if m != nil {
		return m.Digest
	}
	return nil
}

// SealedBytes stores the result of a TPM2_Seal. The private portion (priv) has
// already been encrypted and is no longer sensitive. The hash algorithm is
// assumed to be SHA256.
type SealedBytes struct {
	Priv                 []byte     `protobuf:"bytes,1,opt,name=priv,proto3" json:"priv,omitempty"`
	Pub                  []byte     `protobuf:"bytes,2,opt,name=pub,proto3" json:"pub,omitempty"`
	Pcrs                 []int32    `protobuf:"varint,3,rep,packed,name=pcrs,proto3" json:"pcrs,omitempty"`
	Hash                 HashAlgo   `protobuf:"varint,4,opt,name=hash,proto3,enum=proto.HashAlgo" json:"hash,omitempty"`
	Srk                  ObjectType `protobuf:"varint,5,opt,name=srk,proto3,enum=proto.ObjectType" json:"srk,omitempty"`
	CertifiedPcrs        *Pcrs      `protobuf:"bytes,6,opt,name=certified_pcrs,json=certifiedPcrs,proto3" json:"certified_pcrs,omitempty"`
	CreationData         []byte     `protobuf:"bytes,7,opt,name=creation_data,json=creationData,proto3" json:"creation_data,omitempty"`
	Ticket               *Ticket    `protobuf:"bytes,8,opt,name=ticket,proto3" json:"ticket,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *SealedBytes) Reset()         { *m = SealedBytes{} }
func (m *SealedBytes) String() string { return proto.CompactTextString(m) }
func (*SealedBytes) ProtoMessage()    {}
func (*SealedBytes) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{1}
}

func (m *SealedBytes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SealedBytes.Unmarshal(m, b)
}
func (m *SealedBytes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SealedBytes.Marshal(b, m, deterministic)
}
func (m *SealedBytes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SealedBytes.Merge(m, src)
}
func (m *SealedBytes) XXX_Size() int {
	return xxx_messageInfo_SealedBytes.Size(m)
}
func (m *SealedBytes) XXX_DiscardUnknown() {
	xxx_messageInfo_SealedBytes.DiscardUnknown(m)
}

var xxx_messageInfo_SealedBytes proto.InternalMessageInfo

func (m *SealedBytes) GetPriv() []byte {
	if m != nil {
		return m.Priv
	}
	return nil
}

func (m *SealedBytes) GetPub() []byte {
	if m != nil {
		return m.Pub
	}
	return nil
}

func (m *SealedBytes) GetPcrs() []int32 {
	if m != nil {
		return m.Pcrs
	}
	return nil
}

func (m *SealedBytes) GetHash() HashAlgo {
	if m != nil {
		return m.Hash
	}
	return HashAlgo_HASH_INVALID
}

func (m *SealedBytes) GetSrk() ObjectType {
	if m != nil {
		return m.Srk
	}
	return ObjectType_OBJECT_INVALID
}

func (m *SealedBytes) GetCertifiedPcrs() *Pcrs {
	if m != nil {
		return m.CertifiedPcrs
	}
	return nil
}

func (m *SealedBytes) GetCreationData() []byte {
	if m != nil {
		return m.CreationData
	}
	return nil
}

func (m *SealedBytes) GetTicket() *Ticket {
	if m != nil {
		return m.Ticket
	}
	return nil
}

type ImportBlob struct {
	Duplicate            []byte   `protobuf:"bytes,1,opt,name=duplicate,proto3" json:"duplicate,omitempty"`
	EncryptedSeed        []byte   `protobuf:"bytes,2,opt,name=encrypted_seed,json=encryptedSeed,proto3" json:"encrypted_seed,omitempty"`
	PublicArea           []byte   `protobuf:"bytes,3,opt,name=public_area,json=publicArea,proto3" json:"public_area,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ImportBlob) Reset()         { *m = ImportBlob{} }
func (m *ImportBlob) String() string { return proto.CompactTextString(m) }
func (*ImportBlob) ProtoMessage()    {}
func (*ImportBlob) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{2}
}

func (m *ImportBlob) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ImportBlob.Unmarshal(m, b)
}
func (m *ImportBlob) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ImportBlob.Marshal(b, m, deterministic)
}
func (m *ImportBlob) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ImportBlob.Merge(m, src)
}
func (m *ImportBlob) XXX_Size() int {
	return xxx_messageInfo_ImportBlob.Size(m)
}
func (m *ImportBlob) XXX_DiscardUnknown() {
	xxx_messageInfo_ImportBlob.DiscardUnknown(m)
}

var xxx_messageInfo_ImportBlob proto.InternalMessageInfo

func (m *ImportBlob) GetDuplicate() []byte {
	if m != nil {
		return m.Duplicate
	}
	return nil
}

func (m *ImportBlob) GetEncryptedSeed() []byte {
	if m != nil {
		return m.EncryptedSeed
	}
	return nil
}

func (m *ImportBlob) GetPublicArea() []byte {
	if m != nil {
		return m.PublicArea
	}
	return nil
}

type Pcrs struct {
	Hash                 HashAlgo          `protobuf:"varint,1,opt,name=hash,proto3,enum=proto.HashAlgo" json:"hash,omitempty"`
	Pcrs                 map[uint32][]byte `protobuf:"bytes,2,rep,name=pcrs,proto3" json:"pcrs,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Pcrs) Reset()         { *m = Pcrs{} }
func (m *Pcrs) String() string { return proto.CompactTextString(m) }
func (*Pcrs) ProtoMessage()    {}
func (*Pcrs) Descriptor() ([]byte, []int) {
	return fileDescriptor_63ac7bc02f9d1279, []int{3}
}

func (m *Pcrs) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Pcrs.Unmarshal(m, b)
}
func (m *Pcrs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Pcrs.Marshal(b, m, deterministic)
}
func (m *Pcrs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Pcrs.Merge(m, src)
}
func (m *Pcrs) XXX_Size() int {
	return xxx_messageInfo_Pcrs.Size(m)
}
func (m *Pcrs) XXX_DiscardUnknown() {
	xxx_messageInfo_Pcrs.DiscardUnknown(m)
}

var xxx_messageInfo_Pcrs proto.InternalMessageInfo

func (m *Pcrs) GetHash() HashAlgo {
	if m != nil {
		return m.Hash
	}
	return HashAlgo_HASH_INVALID
}

func (m *Pcrs) GetPcrs() map[uint32][]byte {
	if m != nil {
		return m.Pcrs
	}
	return nil
}

func init() {
	proto.RegisterEnum("proto.ObjectType", ObjectType_name, ObjectType_value)
	proto.RegisterEnum("proto.HashAlgo", HashAlgo_name, HashAlgo_value)
	proto.RegisterType((*Ticket)(nil), "proto.Ticket")
	proto.RegisterType((*SealedBytes)(nil), "proto.SealedBytes")
	proto.RegisterType((*ImportBlob)(nil), "proto.ImportBlob")
	proto.RegisterType((*Pcrs)(nil), "proto.Pcrs")
	proto.RegisterMapType((map[uint32][]byte)(nil), "proto.Pcrs.PcrsEntry")
}

func init() { proto.RegisterFile("tpm.proto", fileDescriptor_63ac7bc02f9d1279) }

var fileDescriptor_63ac7bc02f9d1279 = []byte{
	// 477 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x91, 0x5f, 0x8b, 0xda, 0x40,
	0x14, 0xc5, 0x1b, 0x13, 0xb3, 0x7a, 0x63, 0x6c, 0x3a, 0xb4, 0x65, 0x28, 0x85, 0x06, 0x65, 0x21,
	0xdd, 0x87, 0x85, 0xa6, 0xf4, 0x0f, 0x7d, 0x8b, 0xae, 0xa0, 0xa5, 0x74, 0x25, 0x91, 0xbe, 0xca,
	0x38, 0xb9, 0x5d, 0x53, 0xb3, 0x66, 0x98, 0x8c, 0x0b, 0xf9, 0x14, 0xa5, 0xdf, 0xb8, 0x64, 0x92,
	0x55, 0x9f, 0xf6, 0x25, 0x39, 0x73, 0xee, 0xe1, 0xce, 0xe1, 0x37, 0xd0, 0x57, 0xe2, 0xfe, 0x5a,
	0xc8, 0x42, 0x15, 0xa4, 0xab, 0x7f, 0xa3, 0x18, 0xec, 0x55, 0xc6, 0x77, 0xa8, 0x08, 0x01, 0x4b,
	0x55, 0x02, 0xe9, 0xc0, 0x37, 0x02, 0x37, 0xd6, 0x9a, 0xbc, 0x85, 0xfe, 0x36, 0x43, 0xc9, 0x24,
	0xdf, 0x56, 0xd4, 0xd1, 0x83, 0x93, 0x41, 0x5e, 0x83, 0x9d, 0x66, 0x77, 0x58, 0x2a, 0x0a, 0xbe,
	0x11, 0x0c, 0xe2, 0xf6, 0x34, 0xfa, 0xd7, 0x01, 0x27, 0x41, 0x96, 0x63, 0x3a, 0xa9, 0x14, 0x96,
	0xf5, 0x66, 0x21, 0xb3, 0x07, 0x6a, 0xe8, 0x94, 0xd6, 0xc4, 0x03, 0x53, 0x1c, 0x36, 0xb4, 0xa3,
	0xad, 0x5a, 0xea, 0x14, 0x97, 0x25, 0x35, 0x7d, 0x33, 0xe8, 0xc6, 0x5a, 0x93, 0x31, 0x58, 0x5b,
	0x56, 0x6e, 0xa9, 0xe5, 0x1b, 0xc1, 0x30, 0x7c, 0xde, 0x54, 0xbf, 0x9e, 0xb3, 0x72, 0x1b, 0xe5,
	0x77, 0x45, 0xac, 0x87, 0x64, 0x0c, 0x66, 0x29, 0x77, 0xb4, 0xab, 0x33, 0x2f, 0xda, 0xcc, 0xed,
	0xe6, 0x0f, 0x72, 0xb5, 0xaa, 0x04, 0xc6, 0xf5, 0x94, 0x84, 0x30, 0xe4, 0x28, 0x55, 0xf6, 0x3b,
	0xc3, 0x74, 0xad, 0xef, 0xb1, 0x7d, 0x23, 0x70, 0x42, 0xa7, 0xcd, 0x2f, 0xb9, 0x2c, 0x63, 0xf7,
	0x18, 0x59, 0x36, 0xb7, 0xbb, 0x5c, 0x22, 0x53, 0x59, 0xb1, 0x5f, 0xa7, 0x4c, 0x31, 0x7a, 0xa1,
	0xdb, 0x0e, 0x1e, 0xcd, 0x1b, 0xa6, 0x18, 0xb9, 0x04, 0x5b, 0x69, 0x80, 0xb4, 0xa7, 0x17, 0xba,
	0xed, 0xc2, 0x86, 0x6a, 0xdc, 0x0e, 0x47, 0x12, 0x60, 0x71, 0x2f, 0x0a, 0xa9, 0x26, 0x79, 0xb1,
	0xa9, 0xb9, 0xa6, 0x07, 0x91, 0x67, 0x9c, 0x29, 0x6c, 0xb1, 0x9c, 0x0c, 0x72, 0x09, 0x43, 0xdc,
	0x73, 0x59, 0x09, 0x85, 0xe9, 0xba, 0x44, 0x4c, 0x5b, 0x4c, 0xee, 0xd1, 0x4d, 0x10, 0x53, 0xf2,
	0x0e, 0x1c, 0x71, 0xd8, 0xe4, 0x19, 0x5f, 0x33, 0x89, 0x8c, 0x9a, 0x3a, 0x03, 0x8d, 0x15, 0x49,
	0x64, 0xa3, 0xbf, 0x06, 0x58, 0xcb, 0x73, 0x8c, 0xc6, 0x53, 0x18, 0xdf, 0xb7, 0xfc, 0x3b, 0xbe,
	0x19, 0x38, 0xe1, 0xab, 0x33, 0x2e, 0xfa, 0x33, 0xdb, 0x2b, 0x59, 0x35, 0xcf, 0xf2, 0xe6, 0x0b,
	0xf4, 0x8f, 0x56, 0xfd, 0x92, 0x3b, 0xac, 0xf4, 0x6e, 0x37, 0xae, 0x25, 0x79, 0x09, 0xdd, 0x07,
	0x96, 0x1f, 0xb0, 0xad, 0xdd, 0x1c, 0xbe, 0x75, 0xbe, 0x1a, 0x57, 0x21, 0xc0, 0xe9, 0x61, 0x08,
	0x81, 0xe1, 0xed, 0xe4, 0xfb, 0x6c, 0xba, 0x5a, 0x2f, 0x7e, 0xfe, 0x8a, 0x7e, 0x2c, 0x6e, 0xbc,
	0x67, 0xe4, 0x02, 0xcc, 0x38, 0x89, 0x3c, 0xa3, 0x16, 0xb3, 0xe9, 0xd4, 0x1b, 0x5f, 0x85, 0xd0,
	0x7b, 0x6c, 0x4a, 0x3c, 0x18, 0xcc, 0xa3, 0x64, 0x7e, 0x96, 0xef, 0x81, 0x95, 0xcc, 0xa3, 0x0f,
	0x9e, 0x45, 0x00, 0xec, 0x64, 0x1e, 0x85, 0x9f, 0x3e, 0x7b, 0xce, 0xc6, 0xd6, 0xe5, 0x3f, 0xfe,
	0x0f, 0x00, 0x00, 0xff, 0xff, 0xb2, 0xf2, 0xf8, 0x7d, 0xf0, 0x02, 0x00, 0x00,
}
