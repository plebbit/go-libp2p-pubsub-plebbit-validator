package pubsubPlebbitValidator

import (
    "context"
    "time"
    libp2p "github.com/libp2p/go-libp2p"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "testing"
)

func createPubsubTopic(ctx context.Context) *pubsub.Topic {
    // create libp2p
    host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
    if err != nil {
        panic(err)
    }
    // create pubsub with plebbit validator
    ps, err := pubsub.NewGossipSub(ctx, host, pubsub.WithDefaultValidator(validate))
    if err != nil {
        panic(err)
    }
    // create test pubsub topic
    topic, err := ps.Join("test-topic")
    if err != nil {
        panic(err)
    }
    return topic
}

func publishPubsubMessage(encodedMessage []byte) error {
    ctx := context.Background()
    topic := createPubsubTopic(ctx)
    return topic.Publish(ctx, encodedMessage)
}

func createPubsubChallengeRequestMessage() map[string]interface{} {
    message := map[string]interface{}{}
    message["type"] = "CHALLENGEREQUEST"
    message["timestamp"] = time.Now().Unix()
    message["protocolVersion"] = "1.0.0"
    message["userAgent"] = "/pubsub-plebbit-validator/0.0.1"
    message["challengeRequestId"] = "challenge request id"
    message["acceptedChallengeTypes"] = []string{"image/png"}
    message["encryptedPublication"] = map[string]interface{}{}
    return message
}

func signPubsubMessage(message map[string]interface{}, privateKey []byte) {
    signedPropertyNames := []string{"type", "timestamp", "challengeRequestId", "acceptedChallengeTypes", "encryptedPublication"}
    signature := map[string]interface{}{}
    bytesToSign := getBytesToSign(message, signedPropertyNames)
    signature["signature"] = signEd25519(bytesToSign, privateKey)
    signature["publicKey"] = getPublicKeyFromPrivateKey(privateKey)
    signature["signedPropertyNames"] = signedPropertyNames
    signature["type"] = "ed25519"
    message["signature"] = signature
}

func TestValidPubsubMessage(t *testing.T) {
    privateKey := generatePrivateKey()
    message := createPubsubChallengeRequestMessage()
    signPubsubMessage(message, privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}

func TestInvalidPubsubMessageSignature(t *testing.T) {
    privateKey := generatePrivateKey()
    message := createPubsubChallengeRequestMessage()

    // no signature
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }

    // add signature
    signPubsubMessage(message, privateKey)

    // make signature invalid
    messageSignature, ok := message["signature"].(map[string]interface{})
    if !ok {
        t.Fatalf(`failed convert message.signature to map[string{}]interface{}`)
    }
    signature, ok := messageSignature["signature"].([]byte)
    if !ok {
        t.Fatalf(`failed convert message.signature.signature to []byte`)
    }
    signature[0] = signature[0] + 1
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }
}

func TestInvalidPubsubMessageType(t *testing.T) {
    privateKey := generatePrivateKey()
    message := createPubsubChallengeRequestMessage()

    // make message type invalid
    message["type"] = "INVALID"
    signPubsubMessage(message, privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }

    // other valid message types
    message["type"] = "CHALLENGEREQUEST"
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
    message["type"] = "CHALLENGE"
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
    message["type"] = "CHALLENGEANSWER"
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
    message["type"] = "CHALLENGEVERIFICATION"
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}
