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
    peerScoreParams := NewPeerScoreParams(validator)
    ps, err := pubsub.NewGossipSub(
        ctx, 
        host, 
        pubsub.WithDefaultValidator(validator.Validate),
        pubsub.WithPeerScore(&peerScoreParams, &PeerScoreThresholds),
        pubsub.WithMessageIdFn(MessageIdFn),
    )
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

func TestInvalidPeer(t *testing.T) {
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

func TestPlebbitJsPubsubChallengeRequestMessage(t *testing.T) {
    // create libp2p
    host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
    if err != nil {
        panic(err)
    }
    // create pubsub with plebbit validator
    validator := NewValidator(host)
    // set to ignore timestamp because old hardcoded signature
    validator.noTimestamp = true
    peerScoreParams := NewPeerScoreParams(validator)
    ctx := context.Background()
    ps, err := pubsub.NewGossipSub(
        ctx, 
        host, 
        pubsub.WithDefaultValidator(validator.Validate),
        pubsub.WithPeerScore(&peerScoreParams, &PeerScoreThresholds),
        pubsub.WithMessageIdFn(MessageIdFn),
    )
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

    plebbitJsMessage := []byte{168,100,116,121,112,101,112,67,72,65,76,76,69,78,71,69,82,69,81,85,69,83,84,105,115,105,103,110,97,116,117,114,101,164,100,116,121,112,101,103,101,100,50,53,53,49,57,105,112,117,98,108,105,99,75,101,121,88,32,14,222,199,167,203,37,112,186,9,249,152,27,50,123,24,242,136,235,185,32,176,221,35,178,86,63,252,124,35,84,251,241,105,115,105,103,110,97,116,117,114,101,88,64,173,88,71,192,28,12,11,240,211,109,229,227,91,42,8,204,79,30,185,162,19,245,206,212,39,161,37,180,51,213,213,210,56,197,202,191,105,142,227,219,43,210,254,110,118,180,92,63,157,42,163,231,177,100,32,206,58,128,170,20,8,71,90,8,115,115,105,103,110,101,100,80,114,111,112,101,114,116,121,78,97,109,101,115,133,105,116,105,109,101,115,116,97,109,112,114,99,104,97,108,108,101,110,103,101,82,101,113,117,101,115,116,73,100,118,97,99,99,101,112,116,101,100,67,104,97,108,108,101,110,103,101,84,121,112,101,115,116,101,110,99,114,121,112,116,101,100,80,117,98,108,105,99,97,116,105,111,110,100,116,121,112,101,105,116,105,109,101,115,116,97,109,112,26,100,133,5,46,105,117,115,101,114,65,103,101,110,116,117,47,112,114,111,116,111,99,111,108,45,116,101,115,116,58,49,46,48,46,48,47,111,112,114,111,116,111,99,111,108,86,101,114,115,105,111,110,101,49,46,48,46,48,114,99,104,97,108,108,101,110,103,101,82,101,113,117,101,115,116,73,100,88,38,0,36,8,1,18,32,14,222,199,167,203,37,112,186,9,249,152,27,50,123,24,242,136,235,185,32,176,221,35,178,86,63,252,124,35,84,251,241,116,101,110,99,114,121,112,116,101,100,80,117,98,108,105,99,97,116,105,111,110,164,98,105,118,76,208,123,232,79,172,156,60,230,76,162,124,245,99,116,97,103,80,58,110,62,102,113,220,31,108,11,43,39,190,157,119,42,174,100,116,121,112,101,111,101,100,50,53,53,49,57,45,97,101,115,45,103,99,109,106,99,105,112,104,101,114,116,101,120,116,89,3,188,109,186,200,27,75,223,65,110,170,133,161,143,212,87,34,109,192,52,8,33,236,57,176,83,129,164,19,214,113,135,80,46,69,129,79,14,133,137,127,136,208,224,17,108,237,87,190,147,175,172,160,60,47,236,142,138,140,178,62,25,155,174,235,33,187,221,9,136,161,148,153,75,170,96,172,128,223,242,95,49,115,55,17,55,233,213,219,111,98,6,237,122,102,227,7,108,163,191,85,97,194,75,81,26,89,245,123,29,177,110,211,149,87,66,196,127,71,35,21,13,195,137,247,168,188,19,62,45,162,249,133,153,94,180,97,220,92,18,67,74,145,97,137,228,89,231,207,104,108,87,35,118,231,31,166,220,33,225,77,232,140,202,6,40,55,58,98,214,244,25,105,196,150,21,246,143,222,6,122,135,2,133,133,113,223,29,123,70,114,12,120,74,111,213,207,132,146,73,137,243,6,173,253,159,167,177,48,25,242,199,171,245,32,172,218,182,83,211,47,240,174,37,212,53,12,113,93,174,171,89,15,163,153,120,27,189,13,165,191,125,135,124,98,217,177,105,231,217,120,94,251,38,252,109,113,219,164,147,187,71,19,122,87,33,73,193,33,131,194,207,68,179,236,38,184,130,107,27,111,209,69,152,156,85,234,89,64,218,233,94,87,191,204,236,80,158,164,194,169,238,213,155,43,159,246,201,196,187,75,73,237,187,50,195,128,92,111,113,240,130,78,13,153,144,167,207,77,103,230,157,211,2,201,230,233,204,161,145,167,226,101,200,72,169,248,113,155,12,7,73,92,129,12,83,237,241,71,142,67,92,30,102,45,200,55,74,105,131,66,176,28,227,192,21,238,149,199,241,92,223,88,214,193,188,143,195,169,74,183,88,158,190,238,86,216,236,103,163,230,48,228,238,176,166,81,235,181,183,102,41,192,192,154,168,62,97,92,184,156,120,41,121,199,176,246,18,85,125,156,48,30,150,212,56,205,6,248,95,13,202,2,133,97,169,97,20,160,210,174,5,240,37,243,6,193,129,94,4,6,8,41,175,192,209,99,2,94,251,18,69,27,213,17,90,59,151,99,242,111,187,64,139,23,24,153,131,137,89,202,153,199,244,206,122,82,147,189,34,93,113,157,26,185,184,119,53,106,15,248,247,118,78,184,24,222,199,31,27,190,53,166,181,219,141,20,101,27,184,71,185,203,101,235,79,85,117,80,220,120,77,153,56,87,81,181,156,158,27,74,208,10,119,188,109,229,46,141,44,69,145,220,158,73,202,35,37,100,2,140,22,103,117,127,49,114,213,81,216,135,125,148,141,189,199,218,240,123,216,191,103,71,118,233,74,164,151,60,103,230,9,198,194,114,170,152,12,141,195,143,221,164,143,117,56,199,13,149,33,164,229,205,168,145,21,222,41,208,171,198,99,115,129,221,165,189,246,203,215,85,241,12,76,212,51,197,37,63,12,234,98,213,51,186,217,204,34,187,199,184,120,207,106,152,246,119,177,196,163,116,206,80,230,79,84,45,187,113,252,37,133,130,62,136,209,242,227,99,118,130,13,137,254,104,174,165,7,179,39,74,12,148,248,89,222,117,179,159,123,146,235,109,58,245,139,116,121,55,34,123,232,84,99,191,124,150,156,66,213,97,96,193,48,216,103,32,180,149,119,181,136,56,135,36,117,6,231,29,237,55,66,129,244,249,197,196,23,25,45,31,140,29,219,143,158,120,187,226,68,90,12,161,12,57,53,22,253,171,79,212,138,153,202,73,221,250,121,36,254,89,89,4,184,160,24,166,198,144,192,151,206,170,35,219,21,232,171,196,206,255,87,175,247,143,94,69,113,67,188,189,163,56,170,2,104,228,125,46,200,130,34,9,241,220,211,77,188,52,49,3,233,167,237,107,222,201,118,217,100,70,198,7,243,4,47,16,84,247,144,224,86,255,109,176,30,64,173,181,140,202,56,157,100,201,92,166,28,89,43,19,107,122,9,130,170,61,210,235,31,103,74,65,34,34,94,92,48,177,252,218,85,216,200,232,66,46,122,163,37,212,243,10,176,84,154,118,155,104,215,249,61,70,242,155,94,153,212,50,67,208,39,70,182,14,46,56,252,253,163,7,184,131,141,69,175,132,248,223,97,183,211,201,190,171,43,150,57,118,97,99,99,101,112,116,101,100,67,104,97,108,108,101,110,103,101,84,121,112,101,115,129,105,105,109,97,103,101,47,112,110,103}
    err = topic.Publish(ctx, plebbitJsMessage)
    if (err != nil) {
        t.Fatalf(`publish error is "%v" instead of "<nil>"`, err)
    }
}
