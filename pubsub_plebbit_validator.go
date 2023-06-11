package pubsubPlebbitValidator

import (
    "context"
    "fmt"
    "time"
    "math"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    pubsub_pb "github.com/libp2p/go-libp2p-pubsub/pb"
    peer "github.com/libp2p/go-libp2p/core/peer"
    crypto "github.com/libp2p/go-libp2p/core/crypto"
    lru "github.com/hashicorp/golang-lru/v2"
    host "github.com/libp2p/go-libp2p/core/host"
    blake2b "github.com/minio/blake2b-simd"
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

func validateChallengeRequestId(challengeRequestId []byte, signature Signature, messageType string) bool {
    // challenge request id can only be invalid if from non sub owner, ie CHALLENGEREQUEST or CHALLENGEANSWER
    if messageType != "CHALLENGEREQUEST" && messageType != "CHALLENGEANSWER" {
        return true
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
    // pubsub topic can only be invalid if from sub owner, ie CHALLENGE or CHALLENGEVERIFICATION
    if messageType != "CHALLENGE" && messageType != "CHALLENGEVERIFICATION" {
        return true
    }

    signaturePeerId, err := getPeerIdFromPublicKey(signature.publicKey)
    if (err != nil) {
        fmt.Println("invalid pubsub topic, failed getPeerIdFromPublicKey(signature.publicKey)", err)
        return false
    }
    if (pubsubTopic != signaturePeerId.String()) {
        fmt.Println("invalid pubsub topic, failed pubsubTopic == signaturePeerId")
        return false   
    }
   return true
}

func validateTimestamp(message map[string]interface{}, validator Validator) bool {
    // ignore timestamp for tests that use old hardcoded signatures
    if (validator.noTimestamp) {
        return true
    }

    timestamp, ok := message["timestamp"].(uint64)
    if !ok {
        fmt.Println("invalid message timestamp, failed convert message.timestamp to uint64")
        return false
    }
    now := uint64(time.Now().Unix())
    fiveMinutes := uint64(60 * 5)
    if (timestamp > now + fiveMinutes) {
        fmt.Println("invalid message timestamp, newer than now + 5 minutes")
        return false
    }
    if (timestamp < now - fiveMinutes) {
        fmt.Println("invalid message timestamp, older than 5 minutes")
        return false
    }
    return true
}

func validatePeer(message map[string]interface{}, challengeRequestId []byte, peerId peer.ID, messageType string, validator Validator) bool {
    // nothing to do for challenge message type
    if (messageType == "CHALLENGE") {
        return true
    }

    peerIdString := string(peerId)

    // get challenge request id string
    challengeRequestIdString := string(challengeRequestId)
    if (!validator.challenges.Contains(challengeRequestIdString)) {
        validator.challenges.Add(challengeRequestIdString, make(map[string]bool))
    }
    // get peer hostnames associated with the challenge request id
    challengePeers, _ := validator.challenges.Get(challengeRequestIdString)

    // on challenge verification, challenges and peer statistics are updated with the completed challenge
    if (messageType == "CHALLENGEVERIFICATION") {
        // update the peer hostname completedChallengeCount
        if (validator.peersStatistics.Contains(peerIdString)) {
            peerStatistics, _ := validator.peersStatistics.Get(peerIdString)
            peerStatistics.completedChallengeCount++
        }

        // delete the challenge because it's now completed
        validator.challenges.Remove(challengeRequestIdString)
        return true
    }

    // the 2 message types left are CHALLENGEREQUEST AND CHALLENGEANSWER

    // handle setting Validator.peersStatistics
    if (!validator.peersStatistics.Contains(peerIdString)) {
        validator.peersStatistics.Add(peerIdString, PeerStatistics{1, 0})
    } else {
        peerStatistics, _ := validator.peersStatistics.Get(peerIdString)
        peerStatistics.challengeCount++
    }

    // handle setting Validator.challenges
    challengePeers[peerIdString] = true
    return true
}

type PeerStatistics struct {
    challengeCount uint
    completedChallengeCount uint
}

type Validator struct {
    host host.Host
    challenges *lru.Cache[string, map[string]bool]
    peersStatistics *lru.Cache[string, PeerStatistics]
    noTimestamp bool
}

func NewValidator(host host.Host) Validator {
    challenges, _ := lru.New[string, map[string]bool](10000)
    peersStatistics, _ := lru.New[string, PeerStatistics](10000)
    return Validator{
        host,
        challenges,
        peersStatistics,
        false,
    }
}

func (validator Validator) Validate(ctx context.Context, peerId peer.ID, pubsubMessage *pubsub.Message) bool {
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
    challengeRequestId, ok := message["challengeRequestId"].([]byte)
    if !ok {
        fmt.Println("invalid challenge request id, failed convert message.challengeRequestId to []byte")
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
    validChallengeRequestId := validateChallengeRequestId(challengeRequestId, signature, messageType)
    if (validChallengeRequestId == false) {
        return false
    }

    // validate pubsub topic if from subplebbit owner
    validPubsubTopic := validatePubsubTopic(*pubsubMessage.Topic, signature, messageType)
    if (validPubsubTopic == false) {
        return false
    }

    // validate timestamp
    validTimestamp := validateTimestamp(message, validator)
    if (validTimestamp == false) {
        return false
    }

    // validate too many failed requests forwards
    validPeer := validatePeer(message, challengeRequestId, peerId, messageType, validator)
    if (validPeer == false) {
        return false
    }

    // debug peer validator
    // fmt.Println(validator.challenges.Keys())
    // fmt.Println(validator.peersStatistics.Keys())
    // peerIds := validator.peersStatistics.Keys()
    // for i := 0; i < len(peerIds); i++ {
    //     fmt.Println(validator.peersStatistics.Get(peerIds[i]))
    // }
    // validator.AppSpecificScore(peerId)

    return true
}

var minimumChallengeCount uint = 100
var worstScore float64 = -100000
func (validator Validator) AppSpecificScore(peerId peer.ID) float64 {
    // disable AppSpecificScore until we can test it more
    return 0

    peerStatistics, _ := validator.peersStatistics.Get(string(peerId))

    // need a minimum count for statistics to mean something
    if (peerStatistics.challengeCount < minimumChallengeCount) {
        return 0
    }

    challengeFailureRatio := float64(1 - (peerStatistics.completedChallengeCount / peerStatistics.challengeCount))
    //  1% failure ratio: 0.01²×−100000 = -10
    // 10% failure ratio: 0.10²×−100000 = -1000
    // 50% failure ratio: 0.50²×−100000 = -25000
    // 90% failure ratio: 0.90²×−100000 = -81000
    score := math.Pow(challengeFailureRatio, 2) * worstScore
    return score
}

// make it a validator function so it can be mocked
func (validator Validator) GetNow() uint64 {
    return uint64(time.Now().Unix())
}

// use blake2b because it's faster than sha, copied from https://github.com/filecoin-project/lotus/blob/42d2f4d7e48104c4b8c6f19720e4eef369976442/node/modules/lp2p/pubsub.go
func MessageIdFn(m *pubsub_pb.Message) string {
    hash := blake2b.Sum256(m.Data)
    return string(hash[:])
}
