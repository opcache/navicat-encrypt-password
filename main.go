package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
)

type NavicatPassword struct {
	version    int
	aesKey     []byte
	aesIv      []byte
	blowString string
	blowKey    []byte
	blowIv     []byte
}

func NewNavicatPassword(version int) *NavicatPassword {
	np := &NavicatPassword{
		version:    version,
		aesKey:     []byte("libcckeylibcckey"),
		aesIv:      []byte("libcciv libcciv "),
		blowString: "3DC5CA39",
	}

	np.blowKey = sha1Sum([]byte(np.blowString))
	np.blowIv, _ = hex.DecodeString("d9c7c3c8870d64bd")

	return np
}

func (np *NavicatPassword) Encrypt(stringToEncrypt string) (string, error) {
	switch np.version {
	case 11:
		return np.encryptEleven(stringToEncrypt)
	case 12:
		return np.encryptTwelve(stringToEncrypt)
	default:
		return "", fmt.Errorf("unsupported version")
	}
}

func (np *NavicatPassword) Decrypt(stringToDecrypt string) (string, error) {
	switch np.version {
	case 11:
		return np.decryptEleven(stringToDecrypt)
	case 12:
		return np.decryptTwelve(stringToDecrypt)
	default:
		return "", fmt.Errorf("unsupported version")
	}
}

func (np *NavicatPassword) encryptEleven(stringToEncrypt string) (string, error) {
	round := len(stringToEncrypt) / 8
	leftLength := len(stringToEncrypt) % 8
	result := []byte{}
	currentVector := np.blowIv

	for i := 0; i < round; i++ {
		block := xorBytes([]byte(stringToEncrypt[8*i:8*(i+1)]), currentVector)
		encryptedBlock, err := np.encryptBlock(block)
		if err != nil {
			return "", err
		}
		currentVector = xorBytes(currentVector, encryptedBlock)
		result = append(result, encryptedBlock...)
	}

	if leftLength > 0 {
		currentVector, _ = np.encryptBlock(currentVector)
		result = append(result, xorBytes([]byte(stringToEncrypt[8*round:]), currentVector)...)
	}

	return hex.EncodeToString(result), nil
}

func (np *NavicatPassword) encryptBlock(block []byte) ([]byte, error) {
	cipher, err := des.NewCipher(np.blowKey)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, des.BlockSize)
	cipher.Encrypt(encrypted, block)
	return encrypted, nil
}

func (np *NavicatPassword) decryptBlock(block []byte) ([]byte, error) {
	cipher, err := des.NewCipher(np.blowKey)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, des.BlockSize)
	cipher.Decrypt(decrypted, block)
	return decrypted, nil
}

func (np *NavicatPassword) decryptEleven(upperString string) (string, error) {
	stringToDecrypt, err := hex.DecodeString(upperString)
	if err != nil {
		return "", err
	}

	round := len(stringToDecrypt) / 8
	leftLength := len(stringToDecrypt) % 8
	result := []byte{}
	currentVector := np.blowIv

	for i := 0; i < round; i++ {
		encryptedBlock := stringToDecrypt[8*i : 8*(i+1)]
		decryptedBlock, err := np.decryptBlock(encryptedBlock)
		if err != nil {
			return "", err
		}
		temp := xorBytes(decryptedBlock, currentVector)
		currentVector = xorBytes(currentVector, encryptedBlock)
		result = append(result, temp...)
	}

	if leftLength > 0 {
		currentVector, _ = np.encryptBlock(currentVector)
		result = append(result, xorBytes(stringToDecrypt[8*round:], currentVector)...)
	}

	return string(result), nil
}

func (np *NavicatPassword) encryptTwelve(stringToEncrypt string) (string, error) {
	block, err := aes.NewCipher(np.aesKey)
	if err != nil {
		return "", err
	}

	paddedString := pad([]byte(stringToEncrypt), aes.BlockSize)
	ciphertext := make([]byte, len(paddedString))

	mode := cipher.NewCBCEncrypter(block, np.aesIv)
	mode.CryptBlocks(ciphertext, paddedString)

	return hex.EncodeToString(ciphertext), nil
}

func (np *NavicatPassword) decryptTwelve(upperString string) (string, error) {
	stringToDecrypt, err := hex.DecodeString(upperString)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(np.aesKey)
	if err != nil {
		return "", err
	}

	if len(stringToDecrypt) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	plaintext := make([]byte, len(stringToDecrypt))
	mode := cipher.NewCBCDecrypter(block, np.aesIv)
	mode.CryptBlocks(plaintext, stringToDecrypt)

	return string(unpad(plaintext)), nil
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	dst := make([]byte, n)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

func sha1Sum(data []byte) []byte {
	hash := sha1.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func pad(src []byte, blocksize int) []byte {
	padLen := blocksize - len(src)%blocksize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(src, padding...)
}

func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func main() {
	navicatPassword := NewNavicatPassword(12)

	// 解密
	decode, err := navicatPassword.Decrypt("503AA930968F877F04770B47DD731DC0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(decode)
}
