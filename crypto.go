package pubsubPlebbitValidator

import (
    "crypto/ed25519"
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
