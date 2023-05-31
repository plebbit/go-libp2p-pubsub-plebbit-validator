package pubsubPlebbitValidator

import (
    "context"
    "fmt"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    peer "github.com/libp2p/go-libp2p/core/peer"
    crypto "github.com/libp2p/go-libp2p/core/crypto"
)

func validateSignature(message map[string]interface{}, signature Signature) bool {
    bytesToSign := getBytesToSign(message, signature.signedPropertyNames)
    signatureVerified := verifyEd25519(bytesToSign, signature.signature, signature.publicKey)
    if (signatureVerified == false) {
        fmt.Println("invalid signature")
        return false
    }
    return true
}

func validateType(messageType string) bool {
    if messageType != "CHALLENGEREQUEST" && messageType != "CHALLENGE" && messageType != "CHALLENGEANSWER" && messageType != "CHALLENGEVERIFICATION" {
        fmt.Println("invalid message type")
        return false
    }
    return true
}

func validateChallengeRequestId(message map[string]interface{}, signature Signature) bool {
    challengeRequestId, ok := message["challengeRequestId"].([]byte)
    if !ok {
        fmt.Println("invalid message type, failed convert message.challengeRequestId to []byte")
        return false
    }
    publicKey, err := crypto.UnmarshalEd25519PublicKey(signature.publicKey)
    if (err != nil) {
        fmt.Println("invalid challenge request id, failed crypto.UnmarshalEd25519PublicKey(signature.publicKey)", err)
        return false
    }
    challengeRequestIdPeerId, err := peer.IDFromBytes(challengeRequestId)
    if (err != nil) {
        fmt.Println("invalid challenge request id, failed peer.IDFromPublicKey(signature.publicKey)", err)
        return false
    }
    if (challengeRequestIdPeerId.MatchesPublicKey(publicKey) == false) {
        fmt.Println("invalid challenge request id, failed challengeRequestId.MatchesPublicKey(publicKey)")
        return false
    }
    return true
}

func validatePubsubTopic(pubsubTopic string, signature Signature, messageType string) bool {
    if messageType == "CHALLENGE" || messageType == "CHALLENGEVERIFICATION" {
        signaturePeerId, err := getPeerIdFromPublicKey(signature.publicKey)
        if (err != nil) {
            fmt.Println("invalid pubsub topic, failed getPeerIdFromPublicKey(signature.publicKey)", err)
            return false
        }
        if (pubsubTopic != signaturePeerId.String()) {
            fmt.Println("invalid pubsub topic, failed pubsubTopic == signaturePeerId")
            return false   
        }
    }
    return true
}

func validate(ctx context.Context, peerId peer.ID, pubsubMessage *pubsub.Message) bool {
    // cbor decode
    message, err := cborDecode(pubsubMessage.Data)
    if (err != nil) {
        fmt.Println("failed cbor decode", err)
        return false
    }
    signature, err := toSignature(message["signature"])
    if (err != nil) {
        fmt.Println("invalid signature, failed cbor decode", err)
        return false
    }
    messageType, ok := message["type"].(string)
    if !ok {
        fmt.Println("invalid message type, failed convert message.type to string")
        return false
    }

    // validate message type
    validType := validateType(messageType)
    if (validType == false) {
        return false
    }

    // validate signature
    signed := validateSignature(message, signature)
    if (signed == false) {
        return false
    }

    // validate challengeRequestId if from author
    validChallengeRequestId := validateChallengeRequestId(message, signature)
    if (validChallengeRequestId == false) {
        return false
    }

    // validate pubsub topic if from subplebbit owner
    validPubsubTopic := validatePubsubTopic(*pubsubMessage.Topic, signature, messageType)
    if (validPubsubTopic == false) {
        return false
    }


    // validate too many failed requests forwards

    return true
}
