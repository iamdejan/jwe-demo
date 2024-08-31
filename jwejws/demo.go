package jwejws

import (
	"crypto/rsa"
	"crypto/subtle"
	"fmt"
	"jwe-demo/util"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const secretKey = "jmX604/Rb=a^m&:P4A[{Pm`AWDcA=,"
const dir = "jwejws/"
const encryptionAlg = jwa.RSA_OAEP_256
const signAlg = jwa.HS512

var secretKeyBytes = []byte(secretKey)

func RunDemo() {
	privateKey := util.ParseRSAPrivateKey(dir + "private-key.pem")
	publicKey := util.GetAndWritePublicKey(privateKey, dir+"public-key.pem")

	token, err := jwt.NewBuilder().
		Issuer("gaming laptop").
		IssuedAt(time.Now()).
		Build()
	if err != nil {
		panic(err)
	}
	signKey, err := jwk.FromRaw(secretKeyBytes)
	if err != nil {
		panic(err)
	}

	signSerializer := createSignSerializer(signKey)
	encrypted := generateCombinedJWT(publicKey, signSerializer, token)
	decrypted := decrypt(*privateKey, encrypted)

	signedTokenBytes, err := signSerializer.Serialize(token)
	if err != nil {
		panic(err)
	}
	fmt.Println("signed token = " + string(signedTokenBytes))
	if subtle.ConstantTimeCompare(signedTokenBytes, decrypted) == 0 {
		panic("decrypted information is different")
	}
}

func createSignSerializer(signKey jwk.Key) jwt.Serializer {
	signSerializer := jwt.NewSerializer().Sign(jwt.WithKey(signAlg, signKey))
	return *signSerializer
}

func generateCombinedJWT(publicKey rsa.PublicKey, signSerializer jwt.Serializer, token jwt.Token) []byte {
	serialized, err := signSerializer.
		Encrypt(jwt.WithKey(encryptionAlg, publicKey)).
		Serialize(token)
	if err != nil {
		panic(err)
	}

	fmt.Println("JWS + JWE = " + string(serialized))
	return serialized
}

func decrypt(privateKey rsa.PrivateKey, encrypted []byte) []byte {
	result, err := jwe.Decrypt(encrypted, jwe.WithKey(encryptionAlg, privateKey))
	if err != nil {
		panic(err)
	}

	fmt.Println("decrypted = " + string(result))
	return result
}
