package pubsubPlebbitValidator

import (
    "context"
    "fmt"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    peer "github.com/libp2p/go-libp2p/core/peer"
)

func validateMessageSignature(message map[string]interface{}) bool {
    signature, err := toSignature(message["signature"])
    if (err != nil) {
        fmt.Println("invalid signature, failed cbor decode", err)
        return false
    }

    bytesToSign := getBytesToSign(message, signature.signedPropertyNames)
    signatureVerified := verifyEd25519(bytesToSign, signature.signature, signature.publicKey)
    if (signatureVerified == false) {
        fmt.Println("invalid signature")
        return false
    }
    return true
}

func validateMessageType(message map[string]interface{}) bool {
    messageType, ok := message["type"].(string)
    if !ok {
        fmt.Println("invalid message type, failed convert message.type to string")
        return false
    }

    if messageType != "CHALLENGEREQUEST" && messageType != "CHALLENGE" && messageType != "CHALLENGEANSWER" && messageType != "CHALLENGEVERIFICATION" {
        fmt.Println("invalid message type")
        return false
    }
    return true
}

func validate(ctx context.Context, peerId peer.ID, pubsubMessage *pubsub.Message) bool {
    message, err := cborDecode(pubsubMessage.Data)
    if (err != nil) {
        fmt.Println("failed cbor decode", err)
        return false
    }

    // validate message type
    validType := validateMessageType(message)
    if (validType == false) {
        return false
    }

    // validate signature
    signed := validateMessageSignature(message)
    if (signed == false) {
        return false
    }

    // validate challengeRequestId if from author

    // validate pubsub topic if from subplebbit owner

    return true
}
