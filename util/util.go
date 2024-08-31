package util

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
)

func ParseRSAPrivateKey(path string) *rsa.PrivateKey {
	privateKeyFile, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	buf := bytes.Buffer{}
	_, err = io.Copy(&buf, privateKeyFile)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(buf.Bytes())
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	privateKey, ok := parseResult.(*rsa.PrivateKey)
	if !ok {
		panic("invalid private key")
	}
	return privateKey
}

func GetAndWritePublicKey(privateKey *rsa.PrivateKey, path string) rsa.PublicKey {
	publicKey := privateKey.PublicKey
	writePublicKeyToFile(publicKey, path)
	return publicKey
}

func writePublicKeyToFile(publicKey rsa.PublicKey, path string) {
	pkixPublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPublicKey,
	})

	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		panic(err)
	}
}
