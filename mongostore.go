// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mongostore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// ErrInvalidID ...
var (
	ErrInvalidID = errors.New("store: invalid session id")
)

// Session object store in MongoDB
type Session struct {
	ID       *primitive.ObjectID `bson:"_id,omitempty"`
	Data     string
	Modified time.Time
}

// MongoStore stores sessions in MongoDB
type MongoStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	Token   TokenGetSeter
	coll    *mongo.Collection
}

// NewMongoStore returns a new MongoStore.
// Set ensureTTL to true let the database auto-remove expired object by maxAge.
func NewMongoStore(c *mongo.Collection, maxAge int32, ensureTTL bool,
	keyPairs ...[]byte) *MongoStore {
	store := &MongoStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: int(maxAge),
		},
		Token: &CookieToken{},
		coll:  c,
	}

	store.MaxAge(int(maxAge))

	if ensureTTL {
		opts := options.Index()
		opts.SetBackground(true)
		opts.SetSparse(true)
		opts.SetExpireAfterSeconds(maxAge)
		idx := mongo.IndexModel{Keys: []string{"modified"}, Options: opts}
		_, err := c.Indexes().CreateOne(context.Background(), idx)
		if err != nil {
			fmt.Println("Error occurred while creating index", err)
		}
	}

	return store
}

// Get registers and returns a session for the given name and session store.
// It returns a new session if there are no sessions registered for the name.
func (m *MongoStore) Get(r *http.Request, name string) (
	*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

// New returns a session for the given name without adding it to the registry.
func (m *MongoStore) New(r *http.Request, name string) (
	*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:     m.Options.Path,
		MaxAge:   m.Options.MaxAge,
		Domain:   m.Options.Domain,
		Secure:   m.Options.Secure,
		HttpOnly: m.Options.HttpOnly,
	}
	session.IsNew = true
	var err error
	if cook, errToken := m.Token.GetToken(r, name); errToken == nil {
		err = securecookie.DecodeMulti(name, cook, &session.ID, m.Codecs...)
		if err == nil {
			err = m.load(session)
			if err == nil {
				session.IsNew = false
			} else {
				err = nil
			}
		}
	}
	return session, err
}

// Save saves all sessions registered for the current request.
func (m *MongoStore) Save(r *http.Request, w http.ResponseWriter,
	session *sessions.Session) error {
	if session.Options.MaxAge < 0 {
		if err := m.delete(session); err != nil {
			return err
		}
		m.Token.SetToken(w, session.Name(), "", session.Options)
		return nil
	}

	if session.ID == "" {
		session.ID = primitive.NewObjectID().Hex()
	}

	if err := m.upsert(session); err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		m.Codecs...)
	if err != nil {
		return err
	}

	m.Token.SetToken(w, session.Name(), encoded, session.Options)
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (m *MongoStore) MaxAge(age int) {
	m.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range m.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (m *MongoStore) load(session *sessions.Session) error {
	idObject, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidID
	}

	s := Session{}
	errFind := m.coll.FindOne(context.Background(), bson.M{"_id": idObject}).Decode(&s)
	if errFind != nil {
		return err
	}

	if err := securecookie.DecodeMulti(session.Name(), s.Data, &session.Values,
		m.Codecs...); err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) upsert(session *sessions.Session) error {
	idObject, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidID
	}

	var modified time.Time
	if val, ok := session.Values["modified"]; ok {
		modified, ok = val.(time.Time)
		if !ok {
			return errors.New("mongostore: invalid modified value")
		}
	} else {
		modified = time.Now()
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		m.Codecs...)
	if err != nil {
		return err
	}

	s := Session{
		ID:       &idObject,
		Data:     encoded,
		Modified: modified,
	}

	sMap := bson.M{
		"$set": s,
	}

	count, errFind := m.coll.CountDocuments(context.Background(), bson.M{"_id": idObject})
	if err != nil {
		return errFind
	}

	if count > 0 {
		_, errUpdate := m.coll.UpdateOne(context.Background(), bson.M{"_id": idObject}, sMap)
		if errUpdate != nil {
			return errUpdate
		}
	} else {
		_, errInsert := m.coll.InsertOne(context.Background(), s)
		if errInsert != nil {
			return errInsert
		}
	}

	return nil
}

func (m *MongoStore) delete(session *sessions.Session) error {
	idObject, err := primitive.ObjectIDFromHex(session.ID)
	if err != nil {
		return ErrInvalidID
	}

	_, delError := m.coll.DeleteOne(context.Background(), bson.M{"_id": idObject})
	if delError != nil {
		return delError
	}

	return nil
}
