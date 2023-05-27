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

type Signature struct {
    signature []byte
    publicKey []byte
    signedPropertyNames []string
}

// convert the cbor decoded message["signature"] to a usable Signature
func toSignature(_messageSignature interface{}) (Signature, error) {
    messageSignature, ok := _messageSignature.(map[interface{}]interface{})
    if !ok {
        return Signature{}, errors.New("failed convert message.signature to map[interface{}]interface{}")
    }

    signature, ok := messageSignature["signature"].([]byte)
    if !ok {
        return Signature{}, errors.New("failed convert message.signature.signature to []byte")
    }

    publicKey, ok := messageSignature["publicKey"].([]byte)
    if !ok {
        return Signature{}, errors.New("failed convert message.signature.publicKey to []byte")
    }

    _signedPropertyNames, ok := messageSignature["signedPropertyNames"].([]interface{})
    if !ok {
        return Signature{}, errors.New("failed convert message.signature.signedPropertyNames to []string")
    }
    signedPropertyNames := make([]string, len(_signedPropertyNames))
    for i, name := range _signedPropertyNames {
        str, ok := name.(string)
        if !ok {
            return Signature{}, errors.New("failed convert message.signature.signedPropertyNames to []string")
        }
        signedPropertyNames[i] = str
    }

    return Signature{
        signature,
        publicKey,
        signedPropertyNames,
    }, nil
}
