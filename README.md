mongostore
==========

[Gorilla's Session](http://www.gorillatoolkit.org/pkg/sessions) store implementation with MongoDB

## Requirements

Depends on the [mgo](https://labix.org/v2/mgo) library.

## Installation

    go get github.com/kidstuff/mongostore

## Documentation

Available on [godoc.org](http://www.godoc.org/github.com/kidstuff/mongostore).

### Example

    // Fetch new store.
    dbsess, err := mgo.Dial("localhost")
    if err != nil {
        panic(err)
    }
    defer dbsess.Close()

    store := NewMongoStore(dbsess.DB("test").C("test_session"), 3600, true,
		[]byte("secret-key"))

    // Get a session.
	session, err = store.Get(req, "session-key")
	if err != nil {
        log.Error(err.Error())
    }

    // Add a value.
    session.Values["foo"] = "bar"

    // Save.
    if err = sessions.Save(req, rsp); err != nil {
        t.Fatalf("Error saving session: %v", err)
    }

    // Delete session.
    session.Options.MaxAge = -1
    if err = sessions.Save(req, rsp); err != nil {
        t.Fatalf("Error saving session: %v", err)
    }
