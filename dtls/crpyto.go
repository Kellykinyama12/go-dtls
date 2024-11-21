package dtls

import "C"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"golang.org/x/crypto/curve25519"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// GetHashAlgorithmValue returns the value of the HashAlgorithm as an integer.
//
//export GetHashAlgorithmValue
func GetHashAlgorithmValue(alg byte) int {
	return int(HashAlgorithm(alg))
}

//export generateValueKeyMessage
func generateValueKeyMessage(clientRandom []byte, serverRandom []byte, publicKey []byte) []byte {
	//See signed_params enum: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3

	// logging.Descf(logging.ProtoCRYPTO,
	// 	common.JoinSlice("\n", false,
	// 		common.ProcessIndent("Generating plaintext of signed_params values consist of:", "+", []string{
	// 			fmt.Sprintf("Client Random <u>0x%x</u> (<u>%d bytes</u>)", clientRandom, len(clientRandom)),
	// 			fmt.Sprintf("Server Random <u>0x%x</u> (<u>%d bytes</u>)", serverRandom, len(serverRandom)),
	// 			common.ProcessIndent("ECDH Params:", "", []string{
	// 				fmt.Sprintf("[0]: <u>%s</u>\n[1:2]: <u>%s</u>\n[3]: <u>%d</u> (public key length)", CurveTypeNamedCurve, curve, len(publicKey)),
	// 			}),
	// 			fmt.Sprintf("Public Key: <u>0x%x</u>", publicKey),
	// 		})))
	serverECDHParams := make([]byte, 4)
	serverECDHParams[0] = byte(CurveTypeNamedCurve)
	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(0x001d))
	serverECDHParams[3] = byte(len(publicKey))

	plaintext := []byte{}
	plaintext = append(plaintext, clientRandom...)
	plaintext = append(plaintext, serverRandom...)
	plaintext = append(plaintext, serverECDHParams...)
	plaintext = append(plaintext, publicKey...)
	//logging.Descf(logging.ProtoCRYPTO, "Generated plaintext of signed_params values: <u>0x%x</u> (<u>%d</u> bytes)", plaintext, len(plaintext))
	return plaintext
}

func GetCertificateFingerprint(certificate *tls.Certificate) string {
	return GetCertificateFingerprintFromBytes(certificate.Certificate[0])
}

type EncryptionKeys struct {
	MasterSecret   []byte
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}

//export PHash
func PHash(secret, seed []byte, requestedLength int) ([]byte, error) {
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

	return out[:requestedLength], nil
}

func GenerateEncryptionKeys(masterSecret []byte, clientRandom []byte, serverRandom []byte, keyLen int, ivLen int, hashAlgorithm HashAlgorithm) (*EncryptionKeys, error) {
	//https://github.com/pion/dtls/blob/bee42643f57a7f9c85ee3aa6a45a4fa9811ed122/pkg/crypto/prf/prf.go#L199
	//logging.Descf(logging.ProtoCRYPTO, "Generating encryption keys with Key Length: <u>%d</u>, IV Length: <u>%d</u> via <u>%s</u>, using Master Secret, Server Random, Client Random...", keyLen, ivLen, hashAlgorithm)
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

//export VerifyFinishedData
func VerifyFinishedData(handshakeMessages []byte, serverMasterSecret []byte) ([]byte, error) {
	hashFunc := sha256.New()
	_, err := hashFunc.Write(handshakeMessages)
	if err != nil {
		return nil, err
	}
	seed := append([]byte("server finished"), hashFunc.Sum(nil)...)
	return PHash(serverMasterSecret, seed, 12)
}

// Exported function: Export the private key to a byte slice.
func ExportPrivateKeyToBytes(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return privateKeyBytes, nil
}

// Exported function: Generate server certificate and private key.
func generateServerCertificatePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

//export GenerateServerCertificate
func GenerateServerCertificate(cn string) ([]byte, []byte, error) {
	serverCertificatePrivateKey, err := generateServerCertificatePrivateKey()
	if err != nil {
		return nil, nil, err
	}

	// Generate the certificate using X.509 format
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

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
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

	// Convert certificate and private key to byte slices for export
	certPEM := raw
	privateKeyBytes, err := ExportPrivateKeyToBytes(serverCertificatePrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return certPEM, privateKeyBytes, nil
}

//export GenerateCurveKeypair
func GenerateCurveKeypair() ([]byte, []byte, error) {
	//switch curve {
	//case CurveX25519:
	tmp := make([]byte, 32)
	if _, err := rand.Read(tmp); err != nil {
		return nil, nil, err
	}

	var public, private [32]byte
	copy(private[:], tmp)

	curve25519.ScalarBaseMult(&public, &private)
	return public[:], private[:], nil
	//}
	//return nil, nil, errors.New("not supported curve")
}

// Exported function to generate a key signature.
// func GenerateKeySignature(clientRandom []byte, serverRandom []byte, publicKey []byte, curve Curve, privateKey []byte) ([]byte, error) {
// 	msg := generateValueKeyMessage(clientRandom, serverRandom, publicKey)

// 	//privateKeyObj, ok := privateKey.(*ecdsa.PrivateKey)
// 	privateKeyObj, ok := (*ecdsa.PrivateKey)(privateKey)
// 	if !ok {
// 		return nil, errors.New("not supported private key type")
// 	}

// 	// Hash the message
// 	digest := sha256.Sum256(msg)
// 	hashed := digest[:]

// 	// Sign the hashed message
// 	signed, err := privateKeyObj.Sign(rand.Reader, hashed, crypto.SHA256)
// 	return signed, err
// }

//export GenerateKeySignature
func GenerateKeySignature(clientRandom []byte, serverRandom []byte, publicKey []byte, privateKey []byte) ([]byte, error) {
	// Deserialize the private key from the provided bytes
	privateKeyObj, err := x509.ParseECPrivateKey(privateKey)
	if err != nil {
		return nil, errors.New("failed to parse ECDSA private key")
	}

	// Generate the value key message
	msg := generateValueKeyMessage(clientRandom, serverRandom, publicKey)

	// Hash the message
	digest := sha256.Sum256(msg)
	hashed := digest[:]

	// Sign the hashed message
	signed, err := privateKeyObj.Sign(rand.Reader, hashed, crypto.SHA256)
	if err != nil {
		return nil, errors.New("failed to sign message")
	}

	return signed, nil
}

// Exported function to get certificate fingerprint from raw certificate bytes.
//
//export GetCertificateFingerprintFromBytes
func GetCertificateFingerprintFromBytes(certificate []byte) string {
	fingerprint := sha256.Sum256(certificate)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	return buf.String()
}

//export GeneratePreMasterSecret
func GeneratePreMasterSecret(publicKey []byte, privateKey []byte) ([]byte, error) {
	//switch curve {
	//case CurveX25519:
	result, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, err
	}
	return result, nil
	//}
	//return nil, errors.New("not supported curve type")
}

// Exported function to generate master secret.
func GenerateMasterSecret(preMasterSecret []byte, clientRandom []byte, serverRandom []byte, hashAlgorithm HashAlgorithm) ([]byte, error) {
	seed := append(append([]byte("master secret"), clientRandom...), serverRandom...)
	result, err := PHash(preMasterSecret, seed, 48)
	return result, err
}

// Exported function to generate extended master secret.
func GenerateExtendedMasterSecret(preMasterSecret []byte, handshakeHash []byte) ([]byte, error) {
	seed := append([]byte("extended master secret"), handshakeHash...)
	result, err := PHash(preMasterSecret, seed, 48)
	return result, err
}

// Exported function to generate keying material.
func GenerateKeyingMaterial(masterSecret []byte, clientRandom []byte, serverRandom []byte, hashAlgorithm HashAlgorithm, length int) ([]byte, error) {
	seed := append(append([]byte("EXTRACTOR-dtls_srtp"), clientRandom...), serverRandom...)
	result, err := PHash(masterSecret, seed, length)
	return result, err
}

// Exported function to initialize GCM.
// func InitGCM(masterSecret, clientRandom, serverRandom []byte, cipherSuite CipherSuite) (*GCM, error) {
// 	const prfKeyLen = 16
// 	const prfIvLen = 4
// 	keys, err := GenerateEncryptionKeys(masterSecret, clientRandom, serverRandom, prfKeyLen, prfIvLen, cipherSuite.HashAlgorithm)
// 	if err != nil {
// 		return nil, err
// 	}
// 	gcm, err := NewGCM(keys.ServerWriteKey, keys.ServerWriteIV, keys.ClientWriteKey, keys.ClientWriteIV)
// 	return gcm, err
// }

func generateAEADAdditionalData(h *RecordHeader, payloadLen int) []byte {
	var additionalData [13]byte
	binary.BigEndian.PutUint16(additionalData[:], h.Epoch)
	copy(additionalData[2:], h.SequenceNumber[:])
	additionalData[8] = byte(h.ContentType)
	binary.BigEndian.PutUint16(additionalData[9:], uint16(h.Version))
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(payloadLen))
	return additionalData[:]
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
		//return digest[:]
		hash := digest[:]
		if !ecdsa.Verify(clientCertificatePublicKey, hash, ecdsaSign.R, ecdsaSign.S) {
			return errors.New("key-signature mismatch")
		}
		return nil
	default:
		return errors.New("unsupported certificate type")
	}
}
