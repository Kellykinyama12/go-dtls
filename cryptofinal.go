package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"time"

	"golang.org/x/crypto/curve25519"
)

type ecdsaSignature struct {
	R, S *big.Int
}

//export GetHashAlgorithmValue
func GetHashAlgorithmValue(alg byte) C.int {
	return C.int(HashAlgorithm(alg))
}

//export generateValueKeyMessage
func generateValueKeyMessage(clientRandom []byte, serverRandom []byte, publicKey []byte) *C.uint8_t {
	// Allocating memory for the value key message using C
	serverECDHParams := make([]byte, 4)
	serverECDHParams[0] = byte(CurveTypeNamedCurve)
	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(0x001d))
	serverECDHParams[3] = byte(len(publicKey))

	plaintext := append(clientRandom, serverRandom...)
	plaintext = append(plaintext, serverECDHParams...)
	plaintext = append(plaintext, publicKey...)

	// Allocate memory for the result and copy the bytes
	ptr := C.malloc(C.size_t(len(plaintext)))
	copy((*[1 << 30]byte)(ptr)[:], plaintext)
	return (*C.uint8_t)(ptr)
}

//export PHash
func PHash(secret, seed []byte, requestedLength int) (*C.uint8_t, error) {
	hashFunc := sha256.New
	hmacSHA256 := func(key, data []byte) ([]byte, error) {
		mac := hmac.New(hashFunc, key)
		if _, err := mac.Write(data); err != nil {
			return nil, err
		}
		return mac.Sum(nil), nil
	}

	var err error
	lastRound := seed
	out := []byte{}

	iterations := int(math.Ceil(float64(requestedLength) / float64(hashFunc().Size())))
	for i := 0; i < iterations; i++ {
		lastRound, err = hmacSHA256(secret, lastRound)
		if err != nil {
			return nil, err
		}
		withSecret, err := hmacSHA256(secret, append(lastRound, seed...))
		if err != nil {
			return nil, err
		}
		out = append(out, withSecret...)
	}

	// Allocate C memory for the output and copy the result
	ptr := C.malloc(C.size_t(len(out)))
	copy((*[1 << 30]byte)(ptr)[:], out[:requestedLength])
	return (*C.uint8_t)(ptr), nil
}

//export GenerateEncryptionKeys
func GenerateEncryptionKeys(masterSecret []byte, clientRandom []byte, serverRandom []byte, keyLen int, ivLen int, hashAlgorithm HashAlgorithm) (*EncryptionKeys, error) {
	seed := append(append([]byte("key expansion"), serverRandom...), clientRandom...)
	keyMaterial, err := PHash(masterSecret, seed, (2*keyLen)+(2*ivLen))
	if err != nil {
		return nil, err
	}

	clientWriteKey := keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]

	serverWriteKey := keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]

	clientWriteIV := keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]

	serverWriteIV := keyMaterial[:ivLen]

	return &EncryptionKeys{
		MasterSecret:   masterSecret,
		ClientWriteKey: clientWriteKey,
		ServerWriteKey: serverWriteKey,
		ClientWriteIV:  clientWriteIV,
		ServerWriteIV:  serverWriteIV,
	}, nil
}

//export GenerateServerCertificate
func GenerateServerCertificate(cn string) (*C.uint8_t, *C.uint8_t, error) {
	serverCertificatePrivateKey, err := generateServerCertificatePrivateKey()
	if err != nil {
		return nil, nil, err
	}

	maxBigInt := new(big.Int)
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, _ := rand.Int(rand.Reader, maxBigInt)

	pubKey := &serverCertificatePrivateKey.PublicKey
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Version:      2,
		IsCA:         true,
		Subject: pkix.Name{
			CommonName: "WebRTC-Nuts-and-Bolts",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, serverCertificatePrivateKey)
	if err != nil {
		return nil, nil, err
	}

	// Allocate C memory for the certificate and private key bytes
	certPEM := C.malloc(C.size_t(len(raw)))
	copy((*[1 << 30]byte)(certPEM)[:], raw)
	privateKeyBytes, err := ExportPrivateKeyToBytes(serverCertificatePrivateKey)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPtr := C.malloc(C.size_t(len(privateKeyBytes)))
	copy((*[1 << 30]byte)(privateKeyPtr)[:], privateKeyBytes)

	return (*C.uint8_t)(certPEM), (*C.uint8_t)(privateKeyPtr), nil
}

//export GenerateKeySignature
func GenerateKeySignature(clientRandom []byte, serverRandom []byte, publicKey []byte, privateKey []byte) (*C.uint8_t, error) {
	privateKeyObj, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, errors.New("failed to parse ECDSA private key")
	}

	msg := generateValueKeyMessage(clientRandom, serverRandom, publicKey)
	digest := sha256.Sum256(msg)
	hashed := digest[:]

	signed, err := privateKeyObj.Sign(rand.Reader, hashed, crypto.SHA256)
	if err != nil {
		return nil, errors.New("failed to sign message")
	}

	// Allocate C memory for the signed message
	ptr := C.malloc(C.size_t(len(signed)))
	copy((*[1 << 30]byte)(ptr)[:], signed)
	return (*C.uint8_t)(ptr), nil
}

//export GeneratePreMasterSecret
func GeneratePreMasterSecret(publicKey []byte, privateKey []byte) (*C.uint8_t, error) {
	result, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, err
	}

	// Allocate C memory for the result
	ptr := C.malloc(C.size_t(len(result)))
	copy((*[1 << 30]byte)(ptr)[:], result)
	return (*C.uint8_t)(ptr), nil
}

//export VerifyCertificate
func VerifyCertificate(handshakeMessages []byte, clientSignature []byte, clientCertificates [][]byte) error {
	if len(clientCertificates) == 0 {
		return errors.New("client has not sent any certificate")
	}
	clientCertificate, err := x509.ParseCertificate(clientCertificates[0])
	if err != nil {
		return err
	}
	switch clientCertificatePublicKey := clientCertificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		var ecdsaSign ecdsaSignature
		_, err := asn1.Unmarshal(clientSignature, &ecdsaSign)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(handshakeMessages)
		hash := digest[:]
		if !ecdsa.Verify(clientCertificatePublicKey, hash, ecdsaSign.R, ecdsaSign.S) {
			return errors.New("key-signature mismatch")
		}
		return nil
	default:
		return errors.New("unsupported certificate type")
	}
}
