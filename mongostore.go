// Copyright 2012 The KidStuff Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mongostore

import (
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"labix.org/v2/mgo"
	"labix.org/v2/mgo/bson"
	"net/http"
	"time"
)

var (
	ErrInvalidId = errors.New("mgostore: invalid session id")
)

type MongoStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	coll    *mgo.Collection
}

// Session type
type Session struct {
	Id       bson.ObjectId `bson:"_id,omitempty"`
	Data     string
	Modified time.Time
}

func NewMongoStore(c *mgo.Collection, path string, maxAge int,
	ensureTTL bool, keyPairs ...[]byte) *MongoStore {
	store := &MongoStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   path,
			MaxAge: maxAge,
		},
		coll: c,
	}

	if ensureTTL {
		c.EnsureIndex(mgo.Index{
			Key:         []string{"modified"},
			Background:  true,
			Sparse:      true,
			ExpireAfter: time.Duration(maxAge) * time.Second,
		})
	}

	return store
}

func (m *MongoStore) Get(r *http.Request, name string) (
	*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

func (m *MongoStore) New(r *http.Request, name string) (
	*sessions.Session, error) {
	session := sessions.NewSession(m, name)
	session.Options = &sessions.Options{
		Path:   m.Options.Path,
		MaxAge: m.Options.MaxAge,
	}
	session.IsNew = true
	var err error
	if cook, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, cook.Value, &session.ID, m.Codecs...)
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

func (m *MongoStore) Save(r *http.Request, w http.ResponseWriter,
	session *sessions.Session) error {
	if session.Options.MaxAge < 0 {
		if err := m.delete(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "",
			session.Options))
		return nil
	}

	if session.ID == "" {
		session.ID = bson.NewObjectId().Hex()
	}

	if err := m.upsert(session); err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		m.Codecs...)
	if err != nil {
		return err
	}

	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (m *MongoStore) load(session *sessions.Session) error {
	if !bson.IsObjectIdHex(session.ID) {
		return ErrInvalidId
	}

	s := Session{}
	err := m.coll.FindId(bson.ObjectIdHex(session.ID)).One(&s)
	if err != nil {
		return err
	}

	if err := securecookie.DecodeMulti(session.Name(), s.Data, &session.Values,
		m.Codecs...); err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) upsert(session *sessions.Session) error {
	if !bson.IsObjectIdHex(session.ID) {
		return ErrInvalidId
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
		Id:       bson.ObjectIdHex(session.ID),
		Data:     encoded,
		Modified: modified,
	}

	_, err = m.coll.UpsertId(s.Id, &s)
	if err != nil {
		return err
	}

	return nil
}

func (m *MongoStore) delete(session *sessions.Session) error {
	if !bson.IsObjectIdHex(session.ID) {
		return ErrInvalidId
	}

	return m.coll.RemoveId(bson.ObjectIdHex(session.ID))
}
