package pubsubPlebbitValidator

import (
    "context"
    "time"
    libp2p "github.com/libp2p/go-libp2p"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "testing"
    // "fmt"
    // "reflect"
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

func createPubsubChallengeRequestMessage(privateKey []byte) map[string]interface{} {
    // create message
    message := map[string]interface{}{}
    message["type"] = "CHALLENGEREQUEST"
    message["timestamp"] = time.Now().Unix()
    message["protocolVersion"] = "1.0.0"
    message["userAgent"] = "/pubsub-plebbit-validator/0.0.1"
    message["challengeRequestId"] = "challenge request id"
    message["acceptedChallengeTypes"] = []string{"image/png"}
    message["encryptedPublication"] = map[string]interface{}{}    
    // sign
    signedPropertyNames := []string{"type", "timestamp", "challengeRequestId", "acceptedChallengeTypes", "encryptedPublication"}
    signature := map[string]interface{}{}
    bytesToSign := getBytesToSign(message, signedPropertyNames)
    signature["signature"] = signEd25519(bytesToSign, privateKey)
    signature["publicKey"] = getPublicKeyFromPrivateKey(privateKey)
    signature["signedPropertyNames"] = signedPropertyNames
    signature["type"] = "ed25519"
    message["signature"] = signature
    // encode / decode so exactly like a received message
    decodedMessage, err := cborDecode(cborEncode(message))
    if err != nil {
        panic(err)
    }
    return decodedMessage
}

func TestValidPubsubMessage(t *testing.T) {
    privateKey := generatePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}

func TestInvalidPubsubMessageSignature(t *testing.T) {
    privateKey := generatePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)
    // make the message signature invalid
    signature, _ := toSignature(message["signature"])
    signature.signature[0] = signature.signature[0] + 1
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }
}
