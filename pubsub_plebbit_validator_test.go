package pubsubPlebbitValidator

import (
    "testing"
    "context"
    "time"
    libp2p "github.com/libp2p/go-libp2p"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
)

var subplebbitPrivateKey []byte = []byte{49,69,50,213,51,78,20,35,193,100,36,247,205,129,13,190,124,95,112,200,141,229,111,59,146,66,65,245,169,108,168,184}
var wrongChallengeRequestId []byte = []byte{0,36,8,1,18,32,244,84,230,177,77,214,35,244,185,233,200,209,89,241,126,211,13,198,231,57,165,9,143,70,222,166,20,35,112,60,6,106}

func tryGeneratePrivateKey() ([]byte) {
    privateKey, err := generatePrivateKey()
    if (err != nil) {
        panic(err)
    }
    return privateKey
}

func createPubsubTopic(ctx context.Context, subplebbitPrivateKey []byte) *pubsub.Topic {
    // create libp2p
    host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
    if err != nil {
        panic(err)
    }
    // create pubsub with plebbit validator
    validator := NewValidator(host)
    ps, err := pubsub.NewGossipSub(ctx, host, pubsub.WithDefaultValidator(validator.Validate))
    if err != nil {
        panic(err)
    }
    // create test pubsub topic
    subplebbitPeerId, err := getPeerIdFromPrivateKey(subplebbitPrivateKey)
    if err != nil {
        panic(err)
    }
    // the topic string is always the subplebbit address, which is the the peer id (multihash of public key)
    topicString := subplebbitPeerId.String()
    topic, err := ps.Join(topicString)
    if err != nil {
        panic(err)
    }
    return topic
}

func publishPubsubMessage(encodedMessage []byte) error {
    ctx := context.Background()
    topic := createPubsubTopic(ctx, subplebbitPrivateKey)
    return topic.Publish(ctx, encodedMessage)
}

// use to test invalid pubsub topic
func publishPubsubMessageRandomTopic(encodedMessage []byte) error {
    ctx := context.Background()
    topic := createPubsubTopic(ctx, tryGeneratePrivateKey())
    return topic.Publish(ctx, encodedMessage)
}

func createPubsubChallengeRequestMessage(privateKey []byte) map[string]interface{} {
    message := map[string]interface{}{}
    message["type"] = "CHALLENGEREQUEST"
    message["timestamp"] = time.Now().Unix()
    message["protocolVersion"] = "1.0.0"
    message["userAgent"] = "/pubsub-plebbit-validator/0.0.1"
    message["acceptedChallengeTypes"] = []string{"image/png"}
    message["encryptedPublication"] = map[string]interface{}{}
    // add challenge request id which is multihash of signature.publicKey
    peerId, err := getPeerIdFromPrivateKey(privateKey)
    if (err != nil) {
        panic(err)
    }
    message["challengeRequestId"] = []byte(peerId)
    return message
}

func signPubsubMessage(message map[string]interface{}, privateKey []byte) {
    // sign
    signedPropertyNames := []string{"type", "timestamp", "challengeRequestId", "acceptedChallengeTypes", "encryptedPublication"}
    signature := map[string]interface{}{}
    bytesToSign := getBytesToSign(message, signedPropertyNames)
    signature["signature"] = signEd25519(bytesToSign, privateKey)
    signature["publicKey"] = getPublicKeyFromPrivateKey(privateKey)
    signature["signedPropertyNames"] = signedPropertyNames
    signature["type"] = "ed25519"
    message["signature"] = signature
}

func TestValidPubsubChallengeRequestMessage(t *testing.T) {
    privateKey := tryGeneratePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)
    signPubsubMessage(message, privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}

func TestValidPubsubChallengeAnwserMessage(t *testing.T) {
    privateKey := tryGeneratePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)
    message["type"] = "CHALLENGEANSWER"
    signPubsubMessage(message, privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}

func TestValidPubsubChallengeMessage(t *testing.T) {
    message := createPubsubChallengeRequestMessage(subplebbitPrivateKey)
    message["type"] = "CHALLENGE"
    // make sure sub owner can send any challenge request id they want
    message["challengeRequestId"] = wrongChallengeRequestId
    signPubsubMessage(message, subplebbitPrivateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}

func TestValidPubsubChallengeVerificationMessage(t *testing.T) {
    message := createPubsubChallengeRequestMessage(subplebbitPrivateKey)
    message["type"] = "CHALLENGEVERIFICATION"
    // make sure sub owner can send any challenge request id they want
    message["challengeRequestId"] = wrongChallengeRequestId
    signPubsubMessage(message, subplebbitPrivateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}

func TestInvalidPubsubMessageSignature(t *testing.T) {
    privateKey := tryGeneratePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)

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
    privateKey := tryGeneratePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)

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
    message["type"] = "CHALLENGEANSWER"
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }

    // subplebbit message types, only sub owner can publish challenges or challenge verifications
    subplebbitMessage := createPubsubChallengeRequestMessage(subplebbitPrivateKey)
    subplebbitMessage["type"] = "CHALLENGE"
    // make sure sub owner can send any challenge request id they want
    message["challengeRequestId"] = wrongChallengeRequestId
    signPubsubMessage(subplebbitMessage, subplebbitPrivateKey)
    encodedMessage = cborEncode(subplebbitMessage)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
    subplebbitMessage["type"] = "CHALLENGEVERIFICATION"
    // make sure sub owner can send any challenge request id they want
    message["challengeRequestId"] = wrongChallengeRequestId
    signPubsubMessage(subplebbitMessage, subplebbitPrivateKey)
    encodedMessage = cborEncode(subplebbitMessage)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}

func TestInvalidPubsubMessageChallengeRequestId(t *testing.T) {
    privateKey := tryGeneratePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)

    // make request challenge id invalid (but a real multihash of a public key)
    message["challengeRequestId"] = wrongChallengeRequestId
    signPubsubMessage(message, privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }

    // make request challenge id nil
    message["challengeRequestId"] = nil
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }

    // make request challenge id invalid multihash of public key
    message["challengeRequestId"] = tryGeneratePrivateKey()
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }
}

func TestInvalidPubsubTopic(t *testing.T) {
    privateKey := tryGeneratePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)

    // author message types, should be valid with random topic
    message["type"] = "CHALLENGEREQUEST"
    signPubsubMessage(message, privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessageRandomTopic(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
    message["type"] = "CHALLENGEANSWER"
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessageRandomTopic(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }

    // subplebbit message types, should be invalid with random topic
    subplebbitMessage := createPubsubChallengeRequestMessage(subplebbitPrivateKey)
    subplebbitMessage["type"] = "CHALLENGE"
    signPubsubMessage(subplebbitMessage, subplebbitPrivateKey)
    encodedMessage = cborEncode(subplebbitMessage)
    err = publishPubsubMessageRandomTopic(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }
    subplebbitMessage["type"] = "CHALLENGEVERIFICATION"
    signPubsubMessage(subplebbitMessage, subplebbitPrivateKey)
    encodedMessage = cborEncode(subplebbitMessage)
    err = publishPubsubMessageRandomTopic(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }
}

func TestInvalidPubsubMessageTimestamp(t *testing.T) {
    privateKey := tryGeneratePrivateKey()
    message := createPubsubChallengeRequestMessage(privateKey)

    // make message timestamp invalid
    message["timestamp"] = time.Now().Unix() + int64(60 * 10)
    signPubsubMessage(message, privateKey)
    encodedMessage := cborEncode(message)
    err := publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }
    message["timestamp"] = time.Now().Unix() - int64(60 * 10)
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil && err.Error() != "validation failed") {
        t.Fatalf(`publish error is "%v" instead of "validation failed"`, err)
    }

    // make message timestamp not exactly now, but still valid
    message["timestamp"] = time.Now().Unix() + int64(60 * 4)
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
    message["timestamp"] = time.Now().Unix() - int64(60 * 4)
    signPubsubMessage(message, privateKey)
    encodedMessage = cborEncode(message)
    err = publishPubsubMessage(encodedMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}