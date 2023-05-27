package pubsubPlebbitValidator

import (
    "crypto/ed25519"
    codec "github.com/ugorji/go/codec"
)

func generatePrivateKey() ([]byte, error) {
    _, privateKey, err := ed25519.GenerateKey(nil)
    if err != nil {
        return []byte{}, err
    }
    // the real private key without suffix is .Seed()
    return privateKey.Seed(), nil
}

func getPublicKeyFromPrivateKey(privateKey []byte) ([]byte) {
    // the real private key without suffix is .Seed()
    publicKey := ed25519.NewKeyFromSeed(privateKey).Public().(ed25519.PublicKey)
    return publicKey
}

func signEd25519(bytesToSign []byte, privateKey []byte) ([]byte) {
    // the real private key argument has a suffix so need to use NewKeyFromSeed
    signature := ed25519.Sign(ed25519.NewKeyFromSeed(privateKey), bytesToSign)
    return signature
}

func verifyEd25519(bytesToSign []byte, signature []byte, publicKey []byte) (bool) {
    isValid := ed25519.Verify(publicKey, bytesToSign, signature)
    return isValid
}

func getBytesToSign(message map[string]interface{}, signedPropertyNames []string) []byte {
    // construct the cbor
    propsToSign := map[string]interface{}{}
    for _, propertyName := range signedPropertyNames {
        if (message[propertyName] != nil) {
            propsToSign[propertyName] = message[propertyName]
        }
    }
    var bytesToSign []byte
    cborHandle := &codec.CborHandle{}
    cborHandle.Canonical = true
    encoder := codec.NewEncoderBytes(&bytesToSign, cborHandle)
    encoder.Encode(propsToSign)
    return bytesToSign
}
