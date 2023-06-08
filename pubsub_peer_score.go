package pubsubPlebbitValidator

import (
    "time"
    "net"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    peer "github.com/libp2p/go-libp2p/core/peer"
)

// values copied from https://github.com/filecoin-project/lotus/blob/42d2f4d7e48104c4b8c6f19720e4eef369976442/node/modules/lp2p/pubsub.go
var PeerScoreParams pubsub.PeerScoreParams = pubsub.PeerScoreParams{
    AppSpecificScore: func(p peer.ID) float64 {
        return 0
    },
    AppSpecificWeight: 1,

    // This sets the IP colocation threshold to 5 peers before we apply penalties
    IPColocationFactorThreshold: 5,
    IPColocationFactorWeight:    -100,
    IPColocationFactorWhitelist: []*net.IPNet{},

    // P7: behavioural penalties, decay after 1hr
    BehaviourPenaltyThreshold: 6,
    BehaviourPenaltyWeight:    -10,
    BehaviourPenaltyDecay:     pubsub.ScoreParameterDecay(time.Hour),

    DecayInterval: pubsub.DefaultDecayInterval,
    DecayToZero:   pubsub.DefaultDecayToZero,

    // this retains non-positive scores for 6 hours
    RetainScore: 6 * time.Hour,

    // topic parameters
    // in plebbit all topics are equal so dont set any
    Topics: map[string]*pubsub.TopicScoreParams{},
}

// values copied from https://github.com/filecoin-project/lotus/blob/42d2f4d7e48104c4b8c6f19720e4eef369976442/node/modules/lp2p/pubsub.go
var PeerScoreThresholds pubsub.PeerScoreThresholds = pubsub.PeerScoreThresholds{
    GossipThreshold: -500,
    PublishThreshold: -1000,
    GraylistThreshold: -2500,
    AcceptPXThreshold: 1000,
    OpportunisticGraftThreshold: 3.5,
}
