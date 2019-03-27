# mongostore

[Gorilla's Session](http://www.gorillatoolkit.org/pkg/sessions) store implementation with MongoDB official driver

## Requirements

Depends on the [mongo-driver](https://docs.mongodb.com/ecosystem/drivers/go) library.

## Installation

    go get github.com/kidstuff/mongostore

## Documentation

Available on [godoc.org](http://www.godoc.org/github.com/kidstuff/mongostore).

### Example

```go
    func foo(rw http.ResponseWriter, req *http.Request) {
        // Fetch new store.
        ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
        client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
        if err != nil {
            panic(err)
        }
        defer client.Disconnect(ctx)

        store := mongostore.NewMongoStore(client.Database("test").Collection("test_session"), 3600, true,[]byte("secret-key"))

        // Get a session.
        session, err := store.Get(req, "session-key")
        if err != nil {
            log.Println(err.Error())
        }

        // Add a value.
        session.Values["foo"] = "bar"

        // Save.
        if err = sessions.Save(req, rw); err != nil {
            log.Printf("Error saving session: %v", err)
        }

        fmt.Fprintln(rw, "ok")
    }
```
