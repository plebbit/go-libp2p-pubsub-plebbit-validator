package pubsubPlebbitValidator

import (
    "context"
    // "fmt"
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

func TestPublish(t *testing.T) {
    ctx := context.Background()

    topic := createPubsubTopic(ctx)
    message := []byte("hello")
    topic.Publish(ctx, message)
}
