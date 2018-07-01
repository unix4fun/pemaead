package pemaead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	// TODO: we move away from pbkdf2 -> scrypt/argon2id
	"io"
	"io/ioutil"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

const (
	// argon up to date parameters
	ArgonCostTime    = 2
	ArgonCostMemory  = 256 * 1024
	ArgonCostThreads = 8

	// more up to date parameters
	ScryptCostParam = 65536
	ScryptCostN     = 16
	ScryptCostP     = 4

	// insecure by now..
	Pbkdf2Iteration = 16384

	// ou key length
	KeyLength  = 32
	SaltLength = 32

	/*
		HeaderAesPbkdf  = "AES-256-GCM"
		HeaderAesScrypt = "AES-256-GCM-S"
		HeaderAesArgon  = "AES-256-GCM-A"
	*/

	AEADPemFileHeader = "PEMAEAD FILE"
	AEADFormat        = "AEAD,%02d%02d,%x,%x"

	DerivatePbkdf2 = 0x00
	DerivateScrypt = 0x01
	DerivateArgon2 = 0x02 // Argon2id by default

	CipherAESGCM = 0x00
	//CipherNaCL   = 0x01 // we dont support it yet

	// uint16
	// 0000 0000 // unused for now..
	// 0000 0000
	//       \_this nibble will handle key derivation
	// |
	// \_ this nibble will handle encryption used
	//
	// 00 == pbkdf
	// 01 == scrypt
	// 02 == argon2
	//
	// 00 == aes-gcm
	// 01 == nacl

)

var (
	ErrUnsafe  = errors.New("unsafe option")
	ErrInvalid = errors.New("invalid data")
)

func deriveKey(derivation uint8, salt, password []byte) (dkey []byte, err error) {
	//var dkey []byte

	zero := make([]byte, len(salt))

	switch {
	case len(password) < 5:
		err = ErrUnsafe
		return
	case len(salt) < 8:
		err = ErrUnsafe
		return
	case bytes.Equal(zero, salt):
		err = ErrUnsafe
		return
	}

	switch derivation {
	case DerivatePbkdf2:
		dkey = pbkdf2.Key(password, salt, Pbkdf2Iteration, KeyLength, sha3.New256)
		return
	case DerivateScrypt:
		dkey, err = scrypt.Key([]byte(password), salt, ScryptCostParam, ScryptCostN, ScryptCostP, KeyLength)
		return
	case DerivateArgon2:
		fallthrough
	default:
		dkey = argon2.IDKey([]byte(password), salt, ArgonCostTime, ArgonCostMemory, ArgonCostThreads, KeyLength)
		return
	}
}

type File struct {
	// let's build the header right away
	// buffer we write onto before Close() (== Seal())
	key        []byte
	cipher     uint8
	derivation uint8
	nonce      []byte
	buf        bytes.Buffer
	c          cipher.AEAD
	header     map[string]string
	w          io.Writer
}

//func NewWriter(w io.Writer, password []byte, cipher, derivation uint8) (*AEADPemFile, error) {
func NewWriter(w io.Writer, password []byte, c, d uint8) (io.WriteCloser, error) {
	var nonce []byte
	var aesGcm cipher.AEAD
	salt := make([]byte, SaltLength)

	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	key, err := deriveKey(d, salt, password)
	if err != nil {
		return nil, err
	}

	switch c {
	case CipherAESGCM:
		fallthrough
	default:
		aesBlockCipher, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aesGcm, err = cipher.NewGCM(aesBlockCipher)
		if err != nil {
			return nil, err
		}

		nonce = make([]byte, aesGcm.NonceSize())
		_, err = rand.Read(nonce)
		if err != nil {
			return nil, err
		}
	}

	// build the header, not the nicest but well..
	// ourHeader["DEK-Info"] = "AEAD" + "," + hex.EncodeToString(nonce) + "," + hex.EncodeToString(salt)
	ourHeader := make(map[string]string)
	ourHeader["Proc-Type"] = "4,ENCRYPTED"
	ourHeader["DEK-Info"] = fmt.Sprintf(AEADFormat, c, d, nonce, salt)

	a := &File{
		key:        key,       // already derived
		cipher:     c,         // cipher
		derivation: d,         // derivation
		c:          aesGcm,    // AEAD interface
		nonce:      nonce,     // our Nonce
		header:     ourHeader, // header so that we don't have to build it
		w:          w,         // where we write at the end.
	}

	return a, nil
}

func (a *File) Write(b []byte) (n int, err error) {
	return a.buf.Write(b)
}

func (a *File) Close() (err error) {
	/* encrypt & authenticate, we're done. */
	encrypted := a.c.Seal(nil, a.nonce, a.buf.Bytes(), []byte(a.header["DEK-Info"]))

	pemBlock := &pem.Block{
		Type:    AEADPemFileHeader,
		Headers: a.header,
		Bytes:   encrypted,
	}
	return pem.Encode(a.w, pemBlock)
}

//func NewReader(r io.Reader, password []byte) (*AEADPemFile, error) {
func NewReader(r io.Reader, password []byte) (io.Reader, error) {
	var nonce, salt []byte
	var c, d uint8
	var aesGcm cipher.AEAD

	rawBuf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(rawBuf)
	if pemBlock == nil {
		return nil, ErrInvalid
	}

	if !x509.IsEncryptedPEMBlock(pemBlock) {
		return nil, ErrInvalid
	}

	if pemBlock.Type != AEADPemFileHeader {
		return nil, ErrInvalid
	}

	dek, ok := pemBlock.Headers["DEK-Info"]
	if !ok {
		return nil, ErrInvalid
	}

	_, err = fmt.Sscanf(dek, AEADFormat, &c, &d, &nonce, &salt)
	if err != nil {
		return nil, ErrInvalid
	}

	key, err := deriveKey(d, salt, password)
	if err != nil {
		return nil, ErrInvalid
	}

	switch c {
	case CipherAESGCM:
		fallthrough
	default:
		aesBlockCipher, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrInvalid
		}
		aesGcm, err = cipher.NewGCM(aesBlockCipher)
		if err != nil {
			return nil, ErrInvalid
		}
	}

	if len(nonce) != aesGcm.NonceSize() {
		return nil, ErrInvalid
	}

	plaintext, err := aesGcm.Open(nil, nonce, pemBlock.Bytes, []byte(dek))
	if err != nil {
		return nil, ErrInvalid
	}

	a := &File{
		key:        key,              // already derived
		cipher:     c,                // cipher
		derivation: d,                // derivation
		c:          aesGcm,           // AEAD interface
		nonce:      nonce,            // our Nonce
		header:     pemBlock.Headers, // header so that we don't have to build it
		//w: w writer.
	}

	a.buf.Reset()
	_, err = a.buf.Write(plaintext)
	if err != nil {
		return nil, ErrInvalid
	}
	// let's split the nonce, salt and cipher, derivation
	return a, nil
}

func (a *File) Read(b []byte) (n int, err error) {
	return a.buf.Read(b)
}

// IsEncryptedPemFile take a filename and try to verify if it's a PEM format
// file. The function rely on x509.IsEncryptedPEMBlock() function and return a
// bool.
func IsEncryptedPemFile(file string) bool {
	fileBuf, err := ioutil.ReadFile(file)
	if err != nil {
		return false
	}

	pemBlockBuf, _ := pem.Decode(fileBuf)
	if pemBlockBuf == nil {
		return false
	}
	return x509.IsEncryptedPEMBlock(pemBlockBuf)
}

// AEADDecryptPEMBlock takes a password encrypted PEM block and the password used to
// encrypt it and returns a slice of decrypted DER encoded bytes. It inspects
// the DEK-Info header to determine the algorithm used for decryption. If no
// DEK-Info header is present, an error is returned. If an incorrect password
// is detected an IncorrectPasswordError is returned.

/*
func AEADDecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	AesHash := sha3.New256

	dek, ok := b.Headers["DEK-Info"]
	if !ok {
		return nil, errors.New("AEADDecryptPEMBlock: no DEK-Info header in block")
	}

	dekData := strings.Split(dek, ",")
	if len(dekData) != 3 {
		return nil, errors.New("AEADDecryptPEMBlock: malformed DEK-Info header")
	}

	hexNonce, hexSalt := dekData[1], dekData[2]
	nonce, err := hex.DecodeString(hexNonce)
	if err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(hexSalt)
	if err != nil {
		return nil, err
	}

	if len(salt) != 8 {
		return nil, errors.New("AEADDecryptPEMBlock: incorrect salt size")
	}

	// let's PBKDF2 first..
	ourKey := pbkdf2.Key(password, salt, 16384, 32, AesHash)
	aesraw, err := aes.NewCipher(ourKey)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: AES key setup failed: " + err.Error())
	}
	aesgcm, err := cipher.NewGCM(aesraw)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: GCM failed: " + err.Error())
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, errors.New("AEADDecryptPEMBlock: incorrect nonce size")
	}

	plaintext, err := aesgcm.Open(nil, nonce, b.Bytes, []byte(dek))
	if err != nil {
		return nil, errors.New("AEADDecryptPEMBlock: wrong parameters")
	}

	return plaintext, nil
}
*/

// AEADEncryptPEMBlock returns a PEM block of the specified type holding the
// given DER-encoded data encrypted with AES-GCM256 algorithm, key is derived
// using PBKDF2 on the password.
// Header will be :
/*
func AEADEncryptPEMBlock(rand io.Reader, blockType string, data, password []byte) (*pem.Block, error) {
	hashFunc := sha3.New256

	salt := make([]byte, 8)
	_, err := io.ReadFull(rand, salt)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: no rand: " + err.Error())
	}

	// let's PBKDF2 first..
	ourKey := pbkdf2.Key(password, salt, 16384, 32, hashFunc)
	aesraw, err := aes.NewCipher(ourKey)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: AES key setup failed: " + err.Error())
	}
	aesgcm, err := cipher.NewGCM(aesraw)
	if err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: GCM failed: " + err.Error())
	}

	// this is our nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, errors.New("AEADEncryptPEMBlock: cannot generate Nonce: " + err.Error())
	}

	// allocate data
	//encrypted := make([]byte, len(data)+aesgcm.Overhead())

	// this is our header aka ad
	ourHeader := make(map[string]string)
	ourHeader["Proc-Type"] = "4,ENCRYPTED"
	ourHeader["DEK-Info"] = "AES-256-GCM" + "," + hex.EncodeToString(nonce) + "," + hex.EncodeToString(salt)

	// encrypt & authenticate
	encrypted := aesgcm.Seal(nil, nonce, data, []byte(ourHeader["DEK-Info"]))

	// we're done.
	return &pem.Block{
		Type:    blockType,
		Headers: ourHeader,
		Bytes:   encrypted,
	}, nil
}
*/
