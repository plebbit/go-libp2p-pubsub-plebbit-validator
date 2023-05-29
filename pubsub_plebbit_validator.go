package pubsubPlebbitValidator

import (
    "context"
    "fmt"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    peer "github.com/libp2p/go-libp2p/core/peer"
)

func verifyMessageSignature(message map[string]interface{}) bool {
    signature, err := toSignature(message["signature"])
    if (err != nil) {
        fmt.Println("failed cbor decode", err)
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

func validate(ctx context.Context, peerId peer.ID, pubsubMessage *pubsub.Message) bool {
    // fmt.Println("context", ctx, "peerId", peerId, "pubsubMessage", pubsubMessage)
    message, err := cborDecode(pubsubMessage.Data)
    if (err != nil) {
        fmt.Println("failed cbor decode", err)
        return false
    }

    // validate message type

    // validate signature
    signed := verifyMessageSignature(message)
    if (signed == false) {
        return false
    }

    // validate challengeRequestId if from author

    // validate pubsub topic if from subplebbit owner

    // fmt.Println(message["type"])
    return true
}
