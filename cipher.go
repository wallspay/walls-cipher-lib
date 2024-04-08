package wallscipherlib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	// "encoding/pem"
	"errors"
	"io"
)

type CypherLibrary interface {
    Encrypt(plaintext string) (string, error)
    Decrypt(ciphertext string) (string, error)
}

type AESGCMLibrary struct {
    key []byte
}

func NewAESGCMLibrary(keyString string) (*AESGCMLibrary, error) {
    key := []byte(keyString)
    switch len(key) {
    case 16, 24, 32: // Valid AES key lengths
        return &AESGCMLibrary{key: key}, nil
    default:
        return nil, errors.New("invalid key length: must be 16, 24, or 32 bytes")
    }
}


func (l *AESGCMLibrary) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(l.key)
    if err != nil {
        return "", errors.New("failed to create cipher block: " + err.Error())
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", errors.New("failed to create GCM: " + err.Error())
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        return "", errors.New("failed to create nonce: " + err.Error())
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (l *AESGCMLibrary) Decrypt(encryptedText string) (string, error) {
    ciphertext, err := base64.StdEncoding.DecodeString(encryptedText)
    if err != nil {
        return "", errors.New("failed to decode base64 ciphertext: " + err.Error())
    }

    block, err := aes.NewCipher(l.key)
    if err != nil {
        return "", errors.New("failed to create cipher block: " + err.Error())
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", errors.New("failed to create GCM: " + err.Error())
    }

    if len(ciphertext) < gcm.NonceSize() {
        return "", errors.New("ciphertext too short")
    }

    nonce := ciphertext[:gcm.NonceSize()]
    ciphertext = ciphertext[gcm.NonceSize():]

    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", errors.New("failed to decrypt: " + err.Error())
    }

    return string(plaintext), nil
}

func HashString(plaintext string) (string, error) {
    if plaintext == "" {
        return "", errors.New("input string is empty")
    }
    hasher := sha256.New()
    hasher.Write([]byte(plaintext))
    return hex.EncodeToString(hasher.Sum(nil)), nil
}

type RSAKeysGenerator struct {
    bits int
}

// provides an instance of RSAKeysGenerator with the specifies bits size e.g 1024, 2048 e.t.c
func NewRSAKeysGenerator(bits int) *RSAKeysGenerator {
    return &RSAKeysGenerator{
        bits: bits,
    }
}

// returns a pair of rsa private key bytes and rsa public key bytes. if an error occurs, the return keys will be nil not empty bytes slice.
func (r *RSAKeysGenerator) GenerateKeys() ([]byte, []byte, error) {
    privKey, err := rsa.GenerateKey(rand.Reader, r.bits)
    if err != nil {
        return nil, nil, err
    }

    pubKey := privKey.PublicKey

    privateKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)

    pubKeyBytes := x509.MarshalPKCS1PublicKey(&pubKey)

    // encode private key to PKCS#1 ASN.1 PEM.
    // keyPEM := pem.EncodeToMemory(
    //     &pem.Block{
    //         Type:  "RSA PRIVATE KEY",
    //         Bytes: x509.MarshalPKCS1PrivateKey(privKey),
    //     },
    // )

    // encode public key to PKCS#1 ASN.1 PEM.
    // pubPEM := pem.EncodeToMemory(
    //     &pem.Block{
    //         Type:  "RSA PUBLIC KEY",
    //         Bytes: x509.MarshalPKCS1PublicKey(&pubKey),
    //     },
    // )

    return privateKeyBytes, pubKeyBytes, nil
}
