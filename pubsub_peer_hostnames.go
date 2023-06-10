// this file is not used, but could be used later to block peers based on IP

package pubsubPlebbitValidator

import (
    "fmt"
    peer "github.com/libp2p/go-libp2p/core/peer"
    host "github.com/libp2p/go-libp2p/core/host"
)

func getPeerHostnames(peerId peer.ID, host host.Host) ([]string, error) {
    peerMultiAddresses := host.Peerstore().Addrs(peerId)
    peerHostnames := make([]string, len(peerMultiAddresses))
    for i := 0; i < len(peerMultiAddresses); i++ {
        firstProtocolCode := peerMultiAddresses[i].Protocols()[0].Code
        firstProtocolValue, err := peerMultiAddresses[i].ValueForProtocol(firstProtocolCode)
        if (err != nil) {
            return []string{}, err
        }
        peerHostnames[i] = firstProtocolValue
    }
    return peerHostnames, nil
}

// could be used later to block peers based on IP
func validatePeerHostnames(message map[string]interface{}, challengeRequestId []byte, peerId peer.ID, messageType string, validator Validator) bool {
    // nothing to do for challenge message type
    if (messageType == "CHALLENGE") {
        return true
    }

    // get challenge request id string
    challengeRequestIdString := string(challengeRequestId)
    if (!validator.challenges.Contains(challengeRequestIdString)) {
        validator.challenges.Add(challengeRequestIdString, make(map[string]bool))
    }
    // get peer hostnames associated with the challenge request id
    challengePeerHostnames, _ := validator.challenges.Get(challengeRequestIdString)

    // on challenge verification, challenges and peer statistics are updated with the completed challenge
    if (messageType == "CHALLENGEVERIFICATION") {
        // update the peer hostname completedChallengeCount
        for peerHostname := range challengePeerHostnames {
            if (validator.peersStatistics.Contains(peerHostname)) {
                peerStatistics, _ := validator.peersStatistics.Get(peerHostname)
                peerStatistics.completedChallengeCount++
            }
        }

        // delete the challenge because it's now completed
        validator.challenges.Remove(challengeRequestIdString)
        return true
    }

    // the 2 message types left are CHALLENGEREQUEST AND CHALLENGEANSWER

    // get the peer hostnames of the message sender
    peerHostnames, err := getPeerHostnames(peerId, validator.host)
    if (err != nil) {
        fmt.Println("failed getPeerHostnames(peerId, host)", err)
        return false
    }

    // a peer can have multiple hostnames, iterate over all
    for i := 0; i < len(peerHostnames); i++ {
        // handle setting Validator.peersStatistics
        if (!validator.peersStatistics.Contains(peerHostnames[i])) {
            validator.peersStatistics.Add(peerHostnames[i], PeerStatistics{1, 0})
        } else {
            peerStatistics, _ := validator.peersStatistics.Get(peerHostnames[i])
            peerStatistics.challengeCount++
        }

        // handle setting Validator.challenges
        challengePeerHostnames[peerHostnames[i]] = true
    }
    return true
}
