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
// unsigned char *ptrmoveint(unsigned char *ptr){
//	   ptr += COUNT_MARK_LEN;
//     return ptr;
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

type ABE interface {
	Setup([]byte)
	GenerateInterMediateSecretKey() []byte
	GenerateUserSecretKey(isk1 []byte, isk2 []byte, attr []byte) []byte
	GenerateTKAndRTK(sk []byte) ([]byte, []byte)
	GenerateInterMediateCiphertext() []byte
	EncryptOffline() []byte
	EncryptOnline(plainText []byte, policy []byte, it1 []byte, it2 []byte) ([]byte, int)
	DecryptOffline(ciphertext []byte, ctRet int, tk []byte, it1 []byte, it2 []byte) ([]byte, int)
	DecryptOnline(hrct []byte, rtk []byte, hrct_ret int) []byte
	Free()
}

type abe struct {
	dft *C.uchar
	pk  *C.struct_PK
	msk *C.struct_MSK
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
	v.pk = (*C.struct_PK)(C.malloc(C.sizeof_struct_PK))
	v.msk = (*C.struct_MSK)(C.malloc(C.sizeof_struct_MSK))
	v.dft = (*C.uchar)(unsafe.Pointer(C.CString(string(dft))))
	C.iie_abe_setup(v.pk, v.msk, pp_buf, msk_buf, (*C.uchar)(unsafe.Pointer(v.dft)), C.PK_INIT, (*C.int)(unsafe.Pointer(&ret_len)))
}

// cloud servers generate isks
func (v *abe) GenerateInterMediateSecretKey() []byte {
	isk := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * (C.ISK_UNIT_LEN*(1+iskNum) + C.COUNT_MARK_LEN))))
	defer C.free(unsafe.Pointer(isk))
	var iskRet int
	C.iie_abe_keygen_out(v.pk, isk, C.int(iskNum), (*C.int)(unsafe.Pointer(&iskRet)))
	return v.unsafePointerToBytes(unsafe.Pointer(isk), C.MIN_UNIT_LEN*(C.ISK_UNIT_LEN*(1+iskNum)+C.COUNT_MARK_LEN))
}

// online PKG generate user sk   attr="信息部,运维处,部长"
func (v *abe) GenerateUserSecretKey(isk1 []byte, isk2 []byte, attr []byte) []byte {
	attr1 := (*C.uchar)(unsafe.Pointer(C.CString(string(attr))))
	secretKeyNum := int(C.get_attr_num_from_set(attr1))
	fmt.Printf("secretKeyNum 2: %v \n", secretKeyNum)
	secretKeyLen := C.SK_UNIT_LEN*(secretKeyNum+2) + 3 + int(C.c_strlen((*C.uchar)(unsafe.Pointer(attr1)))) + int(C.c_strlen((*C.uchar)(unsafe.Pointer(v.dft))))
	fmt.Printf("secretKeyLen 548: %v \n", secretKeyLen)
	secretKey := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * secretKeyLen)))
	defer C.free(unsafe.Pointer(secretKey))
	var secretKeyRet int
	C.iie_abe_keygen_pkg(v.msk, (*C.uchar)(unsafe.Pointer(attr1)), (*C.uchar)(unsafe.Pointer(&isk1[0])), (*C.uchar)(unsafe.Pointer(&isk2[0])), secretKey, (*C.int)(unsafe.Pointer(&secretKeyRet)))
	fmt.Printf("secretKeyRet 547: %v\n", secretKeyRet)
	return v.unsafePointerToBytes(unsafe.Pointer(secretKey), C.MIN_UNIT_LEN*secretKeyLen)
}

// PKG generate tk: Conversion Key rtk: Retrieval Key
func (v *abe) GenerateTKAndRTK(sk []byte) ([]byte, []byte) {
	tk := (*C.uchar)(C.malloc(C.ulong(int(C.ptr_size()) * len(sk))))
	rtk := (*C.uchar)(C.malloc(C.ulong(C.ZP_BYTES_LEN)))
	defer C.free(unsafe.Pointer(tk))
	defer C.free(unsafe.Pointer(rtk))
	var tkRet int
	C.iie_abe_keygen_ran(v.pk, (*C.uchar)(unsafe.Pointer(&sk[0])), tk, rtk, (*C.int)(unsafe.Pointer(&tkRet)))
	fmt.Printf("tkRet 547: %v\n", tkRet)
	return v.unsafePointerToBytes(unsafe.Pointer(tk), int(C.ptr_size())*len(sk)), v.unsafePointerToBytes(unsafe.Pointer(rtk), C.ZP_BYTES_LEN)
}

// user offline generate intermediate ciphertext
func (v *abe) GenerateInterMediateCiphertext() []byte {
	it := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * (C.IT_UNIQUE_LEN + itNum*C.IT_UNIT_LEN + C.COUNT_MARK_LEN))))
	defer C.free(unsafe.Pointer(it))
	var itRet int
	C.iie_abe_encrypt_out(v.pk, it, C.int(itNum), (*C.int)(unsafe.Pointer(&itRet)))
	return v.unsafePointerToBytes(unsafe.Pointer(it), C.MIN_UNIT_LEN*(C.IT_UNIQUE_LEN+itNum*C.IT_UNIT_LEN+C.COUNT_MARK_LEN))
}

// user offline encrypt return intermediateCiphertext
func (v *abe) EncryptOffline() []byte {
	intermediateCiphertext := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * (C.IT_UNIQUE_LEN + itNum*C.IT_UNIT_LEN + C.COUNT_MARK_LEN))))
	defer C.free(unsafe.Pointer(intermediateCiphertext))
	var itRet int
	C.iie_abe_encrypt_out(v.pk, intermediateCiphertext, C.int(itNum), (*C.int)(unsafe.Pointer(&itRet)))
	fmt.Printf("itRet: %v\n", itRet)
	return v.unsafePointerToBytes(unsafe.Pointer(intermediateCiphertext), C.MIN_UNIT_LEN*(C.IT_UNIQUE_LEN+itNum*C.IT_UNIT_LEN+C.COUNT_MARK_LEN))
}

// user online encrypt
func (v *abe) EncryptOnline(plainText []byte, policy []byte, it1 []byte, it2 []byte) ([]byte, int) {
	plainText1 := (*C.uchar)(unsafe.Pointer(C.CString(string(plainText))))
	policy1 := (*C.uchar)(unsafe.Pointer(C.CString(string(policy))))
	ctNum := int(C.get_policy_count((*C.char)(unsafe.Pointer(policy1))))
	fmt.Printf("ct_num 3: %v\n", ctNum)
	ctLen := C.CT_UNIQUE_LEN + C.CT_UNIT_LEN*(ctNum+1) + 8 + int(C.c_strlen((*C.uchar)(unsafe.Pointer(policy1)))) + int(C.c_strlen((*C.uchar)(unsafe.Pointer(v.dft)))) + C.COUNT_MARK_LEN*2 + int(C.c_strlen((*C.uchar)(unsafe.Pointer(plainText1)))) + C.IV_LEN + C.TAG_LEN
	fmt.Printf("ct_len 944: %v\n", ctLen)
	ct := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * ctLen)))
	defer C.free(unsafe.Pointer(ct))
	var ctRetLen int
	C.iie_abe_encrypt_user(v.pk, (*C.uchar)(v.bytesToUnsafePointer(it1)), (*C.uchar)(v.bytesToUnsafePointer(it2)), ct, (*C.uchar)(unsafe.Pointer(&policy[0])), (*C.uchar)(unsafe.Pointer(&plainText[0])), (*C.int)(unsafe.Pointer(&ctRetLen)))
	fmt.Printf("ctRetLen 940: %v\n", ctRetLen)
	return v.unsafePointerToBytes(unsafe.Pointer(ct), C.MIN_UNIT_LEN*ctLen), ctRetLen
}

// user offline decrypt
func (v *abe) DecryptOffline(ciphertext []byte, ctRet int, tk []byte, it1 []byte, it2 []byte) ([]byte, int) {
	ptr := (*C.uchar)(v.bytesToUnsafePointer(ciphertext))
	ptr = C.ptrmoveint(ptr)
	sym_dec_len := ctRet - int(C.abe_ct_len((*C.uchar)(v.bytesToUnsafePointer(ciphertext)))) - C.COUNT_MARK_LEN
	fmt.Println("ptr 47: ", int(C.c_strlen(ptr)))
	hrct_len := int(C.c_strlen(ptr)) + C.HRCT_NORMAL_LEN + 1 + sym_dec_len + C.COUNT_MARK_LEN
	fmt.Printf("DecryptOffline hrct_len 475: %v\n", hrct_len)
	hrct := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * hrct_len)))
	defer C.free(unsafe.Pointer(hrct))
	var hrct_ret int
	err := C.iie_abe_decrypt_out(v.pk, (*C.uchar)(v.bytesToUnsafePointer(tk)), (*C.uchar)(v.bytesToUnsafePointer(ciphertext)), C.int(ctRet), hrct, (*C.int)(unsafe.Pointer(&hrct_ret)))
	fmt.Printf("DecryptOffline hrct_ret 475: %v\n", hrct_ret)
	fmt.Printf("DecryptOffline err: %v\n", err)
	return v.unsafePointerToBytes(unsafe.Pointer(hrct), C.MIN_UNIT_LEN*hrct_len), hrct_ret
}

// user online encrytpt
func (v *abe) DecryptOnline(hrct []byte, rtk []byte, hrct_ret int) []byte {
	p_len := hrct_ret - int(C.c_strlen((*C.uchar)(v.bytesToUnsafePointer(hrct)))) - C.COUNT_MARK_LEN - C.IV_LEN - C.TAG_LEN + 1
	fmt.Printf("DecryptOnline p_len : %v\n", p_len)
	var normal_p_ret_len int
	normal_rec_plaintext := (*C.uchar)(C.malloc(C.ulong(C.MIN_UNIT_LEN * p_len)))
	defer C.free(unsafe.Pointer(normal_rec_plaintext))
	err := C.iie_abe_decrypt_user(v.pk, (*C.uchar)(v.bytesToUnsafePointer(rtk)), (*C.uchar)(v.bytesToUnsafePointer(hrct)), C.int(hrct_ret), normal_rec_plaintext, (*C.int)(unsafe.Pointer(&normal_p_ret_len)))
	fmt.Printf("DecryptOnline hrct_ret: %v\n", normal_p_ret_len)
	fmt.Printf("DecryptOnline err: %v\n", err)
	return v.unsafePointerToBytes(unsafe.Pointer(normal_rec_plaintext), normal_p_ret_len)
}

func (v *abe) Free() {
	C.free(unsafe.Pointer(v.dft))
	C.free(unsafe.Pointer(v.pk))
	C.free(unsafe.Pointer(v.msk))
}

func (v *abe) unsafePointerToBytes(ptr unsafe.Pointer, length int) []byte {
	res := make([]uint8, length)
	for i := 0; i < length; i++ {
		c := *(*uint8)(unsafe.Pointer((uintptr(ptr) + unsafe.Sizeof(Byte)*uintptr(i))))
		res[i] = c
	}
	return res
}

func (v *abe) bytesToUnsafePointer(bytes []byte) unsafe.Pointer {
	return unsafe.Pointer(&bytes[0])
}
