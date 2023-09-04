package abe

//#cgo CFLAGS: -I${SRCDIR}/include
//#cgo LDFLAGS: -L${SRCDIR}/lib -labe -L/usr/local/lib -lgmp -lpbc -lcrypto
//
// #include "interface.h"
// #include <stdio.h>
// #include "string.h"
// int ptr_size(){
//     return sizeof(unsigned char *);
// }
// int c_strlen(unsigned char *s){
//     return strlen(s);
// }
// int abe_ct_len(unsigned char *ct){
//     return *(int *)ct;
// }
// int abe_rct_len(unsigned char *rct){
//     return *(int *)rct;
// }
// int abe_hrct_len(unsigned char *hrct){
//     return *(int *)hrct;
// }
// unsigned char* ptr_add_int(unsigned char *ptr){
//     return ptr+sizeof(int);
// }
// int ptr_len(unsigned char *ptr){
//     return strlen((const char *)ptr);
// }
import "C"
import (
	"fmt"
	"unsafe"
)

const (
	Byte uint8 = 0
)

var iskNum int = 5
var itNum int = 5
var sk_len int

type ABE interface {
	Setup([]byte)
}

type abe struct {
	dft []byte
	pk  C.struct_PK
	msk C.struct_MSK
}

func New() (ABE, error) {
	a := &abe{}
	return a, nil
}

// PKG setup pk msk dft="信息部"
func (v *abe) Setup(dft []byte) {
	pk := (*C.struct_PK)(C.malloc(C.sizeof_struct_PK))
	defer C.free(unsafe.Pointer(pk))
	msk := (*C.struct_MSK)(C.malloc(C.sizeof_struct_MSK))
	defer C.free(unsafe.Pointer(msk))
	var ret_len int
	pp_len := C.PP_BYTES_LEN + len(dft) + C.MIN_UNIT_LEN
	pp_buf := (*C.uchar)(C.malloc(C.ulong(pp_len)))
	msk_buf := (*C.uchar)(C.malloc(C.ulong(C.ZP_BYTES_LEN)))
	C.iie_abe_setup(pk, msk, pp_buf, msk_buf, (*C.uchar)(unsafe.Pointer(&dft)), C.PK_INIT, (*C.int)(unsafe.Pointer(&ret_len)))
	v.dft = dft
	v.pk = *pk
	v.msk = *msk
}

// cloud servers generate isks
func (v *abe) GenerateInterMediateSecretKey() []byte {
	isk := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * (C.ISK_UNIT_LEN*(1+iskNum) + C.COUNT_MARK_LEN))))
	defer C.free(unsafe.Pointer(isk))
	var iskRet int
	C.iie_abe_keygen_out(&v.pk, isk, C.int(iskNum), (*C.int)(unsafe.Pointer(&iskRet)))
	fmt.Printf("iskRet %v\n", iskRet)
	return v.unsafePointerToBytes(unsafe.Pointer(isk), iskRet)
}

// online PKG generate user sk   attr="信息部,运维处,部长"
func (v *abe) GenerateUserSecretKey(isk1 []byte, isk2 []byte, attr []byte) []byte {
	secretKeyNum := int(C.get_attr_num_from_set((*C.uchar)(unsafe.Pointer(&attr[0]))))
	fmt.Printf("secretKeyNum: %v \n", secretKeyNum)
	secretKeyLen := C.SK_UNIT_LEN*(secretKeyNum+2) + 3 + cgoStrlen(attr) + cgoStrlen(v.dft)
	secretKey := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * secretKeyLen)))
	sk_len = secretKeyLen
	defer C.free(unsafe.Pointer(secretKey))
	var secretKeyRet int
	C.iie_abe_keygen_pkg(&v.msk, (*C.uchar)(unsafe.Pointer(&attr[0])), (*C.uchar)(v.bytesToUnsafePointer(isk1)), (*C.uchar)(v.bytesToUnsafePointer(isk2)), secretKey, (*C.int)(unsafe.Pointer(&secretKeyRet)))
	fmt.Printf("secretKeyRet %v\n", secretKeyRet)
	return v.unsafePointerToBytes(unsafe.Pointer(secretKey), secretKeyRet)
}

// PKG generate tk: Conversion Key rtk: Retrieval Key
func (v *abe) GenerateTKAndRTK(sk []byte) ([]byte, []byte) {
	tk := (*C.uchar)(C.malloc(C.ulong(int(C.ptr_size()) * sk_len)))
	rtk := (*C.uchar)(C.malloc(C.ulong(C.ZP_BYTES_LEN)))
	defer C.free(unsafe.Pointer(tk))
	defer C.free(unsafe.Pointer(rtk))
	var tkRet int
	C.iie_abe_keygen_ran(&v.pk, (*C.uchar)(v.bytesToUnsafePointer(sk)), tk, rtk, (*C.int)(unsafe.Pointer(&tkRet)))
	fmt.Printf("tkRet: %v\n", tkRet)
	return v.unsafePointerToBytes(unsafe.Pointer(tk), sk_len), v.unsafePointerToBytes(unsafe.Pointer(rtk), sk_len)
}

// user offline generate intermediate ciphertext
func (v *abe) GenerateIntermediateCiphertext() []byte {
	it := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * (C.IT_UNIQUE_LEN + itNum*C.IT_UNIT_LEN + C.COUNT_MARK_LEN))))
	defer C.free(unsafe.Pointer(it))
	var itRet int
	C.iie_abe_encrypt_out(&v.pk, it, C.int(itNum), (*C.int)(unsafe.Pointer(&itRet)))
	return v.unsafePointerToBytes(unsafe.Pointer(it), itRet)
}

func (v *abe) unsafePointerToBytes(ptr unsafe.Pointer, length int) []byte {
	res := make([]uint8, length)
	for i := 0; i < length; i++ {
		c := *(*uint8)(unsafe.Pointer((uintptr(ptr) + unsafe.Sizeof(Byte)*uintptr(i))))
		res[i] = c
	}
	return res
}

// TODO possible page fault
func (v *abe) bytesToUnsafePointer(bytes []byte) unsafe.Pointer {
	return unsafe.Pointer(&bytes[0])
}

func cgoStrlen(s []uint8) int {
	return int(C.c_strlen((*C.uchar)(unsafe.Pointer(&s[0]))))
}
