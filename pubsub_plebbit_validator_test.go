package pubsubPlebbitValidator

import (
    "context"
    "fmt"
    "time"
    libp2p "github.com/libp2p/go-libp2p"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    codec "github.com/ugorji/go/codec"
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

func createChallengeRequestMessage(privateKey []byte) map[string]interface{} {
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

    return message
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
    cbor := codec.NewEncoderBytes(&bytesToSign, new(codec.CborHandle))
    cbor.Encode(propsToSign)
    return bytesToSign
}

func TestPublish(t *testing.T) {
    privateKey, err := generatePrivateKey()
    if (err != nil) {
        panic(err)
    }
    message := createChallengeRequestMessage(privateKey)

    // encode message
    var encodedMessage []byte
    cbor := codec.NewEncoderBytes(&encodedMessage, new(codec.CborHandle))
    cbor.Encode(message)

    fmt.Println("message", message, "encodedMessage", encodedMessage)

    // publish message
    ctx := context.Background()
    topic := createPubsubTopic(ctx)
    topic.Publish(ctx, encodedMessage)
}
