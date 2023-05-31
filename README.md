#### Usage

```go
import (
    libp2p "github.com/libp2p/go-libp2p"
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    plebbitValidator "github.com/plebbit/go-libp2p-pubsub-plebbit-validator"
)

func main() {
    // create libp2p
    host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
    if err != nil {
        panic(err)
    }

    // create pubsub with plebbit validator
    ctx := context.Background()
    ps, err := pubsub.NewGossipSub(ctx, host, pubsub.WithDefaultValidator(plebbitValidator.validate))
    if err != nil {
        panic(err)
    }

    // create test pubsub topic
    topic, err := ps.Join("test-topic")
    if err != nil {
        panic(err)
    }

    message := []byte("hello")
    topic.Publish(ctx, message)
}
```

#### Test

```sh
go test
```
