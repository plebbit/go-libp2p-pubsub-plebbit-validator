package pubsubPlebbitValidator

import (
    "crypto/ed25519"
    crypto "github.com/libp2p/go-libp2p/core/crypto"
    peer "github.com/libp2p/go-libp2p/core/peer"
)

func generatePrivateKey() ([]byte, error) {
    _, privateKey, err := ed25519.GenerateKey(nil)
    // the real private key without suffix is .Seed()
    return privateKey.Seed(), err
}

func getPublicKeyFromPrivateKey(privateKey []byte) ([]byte) {
    // the real private key without suffix is .Seed()
    publicKey := ed25519.NewKeyFromSeed(privateKey).Public().(ed25519.PublicKey)
    return publicKey
}

func getPeerIdFromPublicKey(publicKeyBytes []byte) (peer.ID, error) {
    publicKey, err := crypto.UnmarshalEd25519PublicKey(publicKeyBytes)
    if (err != nil) {
        errPeerId, _ := peer.IDFromBytes([]byte{})
        return errPeerId, err
    }
    peerId, err := peer.IDFromPublicKey(publicKey)
    if (err != nil) {
        errPeerId, _ := peer.IDFromBytes([]byte{})
        return errPeerId, err
    }
    return peerId, err
}

func getPeerIdFromPrivateKey(privateKey []byte) (peer.ID, error) {
    return getPeerIdFromPublicKey(getPublicKeyFromPrivateKey(privateKey))
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
    return cborEncode(propsToSign)
}
