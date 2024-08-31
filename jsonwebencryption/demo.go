package jsonwebencryption

import (
	"crypto/rsa"
	"crypto/subtle"
	"fmt"

	"jwe-demo/util"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

const dir = "jsonwebencryption/"
const payload = "lorem ipsum dolor sit amet"
const alg = jwa.RSA_OAEP_256

var payloadBytes = []byte(payload)

func RunDemo() {
	privateKey := util.ParseRSAPrivateKey(dir + "private-key.pem")
	publicKey := util.GetAndWritePublicKey(privateKey, dir+"public-key.pem")

	result := encrypt(publicKey, payloadBytes)
	decrypt(*privateKey, result)
}

func encrypt(publicKey rsa.PublicKey, data []byte) []byte {
	result, err := jwe.Encrypt([]byte(data), jwe.WithKey(alg, publicKey))
	if err != nil {
		panic(err)
	}
	fmt.Println("encrypt = " + string(result))

	return result
}

func decrypt(privateKey rsa.PrivateKey, encrypted []byte) {
	result, err := jwe.Decrypt(encrypted, jwe.WithKey(alg, privateKey))
	if err != nil {
		panic(err)
	}
	if subtle.ConstantTimeCompare(payloadBytes, result) == 0 {
		panic("decrypted information is different")
	}
	fmt.Println("decrypt = " + string(result))
}
