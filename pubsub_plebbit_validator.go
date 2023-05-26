package pubsubPlebbitValidator

import (
	"context"
	"fmt"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	peer "github.com/libp2p/go-libp2p/core/peer"
)

func validate(ctx context.Context, peerId peer.ID, pubsubMessage *pubsub.Message) bool {
	fmt.Println("context", ctx, "peerId", peerId, "pubsubMessage", pubsubMessage)
	return true
}
