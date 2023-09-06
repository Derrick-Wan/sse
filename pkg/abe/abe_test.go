package abe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Decrypt(t *testing.T) {
	// key generate
	abe, err := New()
	assert.NoError(t, err)
	dft_str := []uint8("信息部")
	abe.Setup(dft_str)
	isk1 := abe.GenerateInterMediateSecretKey()
	isk2 := abe.GenerateInterMediateSecretKey()
	attr := []uint8("运维处,部长")
	sk := abe.GenerateUserSecretKey(isk1, isk2, attr)
	//tk rtk
	tk, rtk := abe.GenerateTKAndRTK(sk)
	// encrypt
	it1 := abe.EncryptOffline()
	it2 := abe.EncryptOffline()
	policy := []uint8("(财务处 or 运维处) and 部长")
	plainText := []uint8("hello world")
	ct, ct_ret := abe.EncryptOnline(plainText, policy, it1, it2)
	// decrypt
	hrct, hrctRet := abe.DecryptOffline(ct, ct_ret, tk, it1, it2)
	res := abe.DecryptOnline(hrct, rtk, hrctRet)
	assert.Equal(t, string(plainText), string(res))
	abe.Free()

}
