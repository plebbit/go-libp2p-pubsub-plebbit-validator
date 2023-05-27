package pubsubPlebbitValidator

import (
    "errors"
    codec "github.com/ugorji/go/codec"
)

func cborDecode(encoded []byte) (map[string]interface{}, error) {
    cborHandle := &codec.CborHandle{}
    cborHandle.Canonical = true
    var decoder = codec.NewDecoderBytes(encoded, cborHandle)
    var decoded map[string]interface{}
    err := decoder.Decode(&decoded)
    if (err != nil) {
        return decoded, err
    }
    return decoded, err
}

func cborEncode(decoded map[string]interface{}) ([]byte) {
    var encoded []byte
    cborHandle := &codec.CborHandle{}
    cborHandle.Canonical = true
    encoder := codec.NewEncoderBytes(&encoded, cborHandle)
    encoder.Encode(decoded)
    return encoded
}

func getSignatureFromMessage(message map[string]interface{}) ([]byte, error) {
    err := errors.New("failed convert message.signature.signature to []byte")
    signature, ok := message["signature"].(map[interface{}]interface{})
    if !ok {
        return []byte{}, err
    }
    signatureBytes, ok := signature["signature"].([]byte)
    if !ok {
        return []byte{}, err
    }
    return signatureBytes, nil
}

func getSignedPropertyNamesFromMessage(message map[string]interface{}) ([]string, error) {
    err := errors.New("failed convert message.signature.signedPropertyNames to []string")
    signature, ok := message["signature"].(map[interface{}]interface{})
    if !ok {
        return []string{}, err
    }
    _signedPropertyNames, ok := signature["signedPropertyNames"].([]interface{})
    if !ok {
        return []string{}, err
    }
    signedPropertyNames := make([]string, len(_signedPropertyNames))
    for i, name := range _signedPropertyNames {
        str, ok := name.(string)
        if !ok {
            return []string{}, err
        }
        signedPropertyNames[i] = str
    }
    return signedPropertyNames, nil
}

func getPublicKeyFromMessage(message map[string]interface{}) ([]byte, error) {
    err := errors.New("failed convert message.signature.publicKey to []byte")
    signature, ok := message["signature"].(map[interface{}]interface{})
    if !ok {
        return []byte{}, err
    }
    publicKeyBytes, ok := signature["publicKey"].([]byte)
    if !ok {
        return []byte{}, err
    }
    return publicKeyBytes, nil
}
