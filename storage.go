/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package mgohkp

import (
	"bytes"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/errgo.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	hkpstorage "gopkg.in/hockeypuck/hkp.v0/storage"
	"gopkg.in/hockeypuck/openpgp.v0"
)

const (
	defaultDBName         = "hkp"
	defaultCollectionName = "keys"
	maxFingerprintLen     = 40
)

type storage struct {
	*mgo.Session
	dbName, collectionName string

	mu        sync.Mutex
	listeners []func(hkpstorage.KeyChange) error
}

var _ hkpstorage.Storage = (*storage)(nil)

// NewStorage returns a MongoDB storage implementation for an HKP service.
func NewStorage(session *mgo.Session) (hkpstorage.Storage, error) {
	st := &storage{
		Session:        session,
		dbName:         defaultDBName,
		collectionName: defaultCollectionName,
	}
	err := st.createIndexes()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return st, nil
}

func (st *storage) createIndexes() error {
	session, c := st.c()
	defer session.Close()

	for _, index := range []mgo.Index{{
		Key:    []string{"rfingerprint"},
		Unique: true,
	}, {
		Key:    []string{"md5"},
		Unique: true,
	}, {
		Key: []string{"mtime"},
	}, {
		Key:        []string{"keywords"},
		Background: true,
	}} {
		err := c.EnsureIndex(index)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func (st *storage) c() (*mgo.Session, *mgo.Collection) {
	session := st.Session.Copy()
	return session, session.DB(st.dbName).C(st.collectionName)
}

type keyDoc struct {
	RFingerprint string   `bson:"rfingerprint"`
	CTime        int64    `bson:"ctime"`
	MTime        int64    `bson:"mtime"`
	MD5          string   `bson:"md5"`
	Packets      []byte   `bson:"packets"`
	Keywords     []string `bson:"keywords"`
}

func (st *storage) MatchMD5(md5s []string) ([]string, error) {
	session, c := st.c()
	defer session.Close()

	for i := range md5s {
		md5s[i] = strings.ToLower(md5s[i])
	}

	var result []string
	var doc keyDoc

	iter := c.Find(bson.D{{"md5", bson.D{{"$in", md5s}}}}).Iter()
	for iter.Next(&doc) {
		result = append(result, doc.RFingerprint)
	}
	err := iter.Close()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

// Resolve implements storage.Storage.
//
// Only v4 key IDs are resolved by this backend. v3 short and long key IDs
// currently won't match.
func (st *storage) Resolve(keyids []string) ([]string, error) {
	session, c := st.c()
	defer session.Close()

	for i := range keyids {
		keyids[i] = strings.ToLower(keyids[i])
	}

	var result []string
	var doc keyDoc

	var regexes []interface{}
	for _, keyid := range keyids {
		if len(keyid) < maxFingerprintLen {
			regexes = append(regexes, bson.RegEx{Pattern: "^" + keyid})
		} else {
			result = append(result, keyid)
		}
	}

	if len(regexes) > 0 {
		iter := c.Find(bson.D{{"rfingerprint", bson.D{{"$in", regexes}}}}).Iter()
		for iter.Next(&doc) {
			result = append(result, doc.RFingerprint)
		}
		err := iter.Close()
		if err != nil {
			return nil, errgo.Mask(err)
		}
	}

	return result, nil
}

func (st *storage) MatchKeyword(keywords []string) ([]string, error) {
	session, c := st.c()
	defer session.Close()

	// Split these on spaces, to support multiple-word searches.
	var match []string
	for i := range keywords {
		keywords[i] = strings.ToLower(keywords[i])
		for _, part := range strings.Split(keywords[i], " ") {
			if part != "" {
				match = append(match, part)
			}
		}
	}

	var result []string
	var doc keyDoc

	iter := c.Find(bson.D{{"keywords", bson.D{{"$elemMatch", bson.D{{"$in", match}}}}}}).Limit(100).Iter()
	for iter.Next(&doc) {
		result = append(result, doc.RFingerprint)
	}
	err := iter.Close()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

func (st *storage) ModifiedSince(t time.Time) ([]string, error) {
	session, c := st.c()
	defer session.Close()

	var result []string
	var doc keyDoc

	iter := c.Find(bson.D{{"mtime", bson.D{{"$gt", t.Unix()}}}}).Limit(100).Iter()
	for iter.Next(&doc) {
		result = append(result, doc.RFingerprint)
	}
	err := iter.Close()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

func (st *storage) FetchKeys(rfps []string) ([]*openpgp.Pubkey, error) {
	session, c := st.c()
	defer session.Close()

	for i := range rfps {
		rfps[i] = strings.ToLower(rfps[i])
	}

	var result []*openpgp.Pubkey
	var doc keyDoc

	iter := c.Find(bson.D{{"rfingerprint", bson.D{{"$in", rfps}}}}).Limit(100).Iter()
	for iter.Next(&doc) {
		pubkey, err := readOneKey(doc.Packets, doc.RFingerprint)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		result = append(result, pubkey)
	}
	err := iter.Close()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

func (st *storage) FetchKeyrings(rfps []string) ([]*hkpstorage.Keyring, error) {
	session, c := st.c()
	defer session.Close()

	for i := range rfps {
		rfps[i] = strings.ToLower(rfps[i])
	}

	var result []*hkpstorage.Keyring
	var doc keyDoc

	iter := c.Find(bson.D{{"rfingerprint", bson.D{{"$in", rfps}}}}).Limit(100).Iter()
	for iter.Next(&doc) {
		pubkey, err := readOneKey(doc.Packets, doc.RFingerprint)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		result = append(result, &hkpstorage.Keyring{
			Pubkey: pubkey,
			CTime:  time.Unix(doc.CTime, 0),
			MTime:  time.Unix(doc.MTime, 0),
		})
	}
	err := iter.Close()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

func readOneKey(b []byte, rfingerprint string) (*openpgp.Pubkey, error) {
	c := openpgp.ReadKeys(bytes.NewBuffer(b))
	defer func() {
		for _ = range c {
		}
	}()
	var result *openpgp.Pubkey
	for readKey := range c {
		if readKey.Error != nil {
			return nil, errgo.Mask(readKey.Error)
		}
		if result != nil {
			return nil, errgo.Newf("multiple keys in keyring: %v, %v", result.Fingerprint(), readKey.Fingerprint())
		}
		if readKey.Pubkey.RFingerprint != rfingerprint {
			return nil, errgo.Newf("RFingerprint mismatch: expected=%q got=%q",
				rfingerprint, readKey.Pubkey.RFingerprint)
		}
		result = readKey.Pubkey
	}
	return result, nil
}

func (st *storage) Insert(keys []*openpgp.Pubkey) error {
	session, c := st.c()
	defer session.Close()

	for _, key := range keys {
		openpgp.Sort(key)

		var buf bytes.Buffer
		err := openpgp.WritePackets(&buf, key)
		if err != nil {
			return errgo.Mask(err)
		}

		now := time.Now().Unix()
		doc := keyDoc{
			CTime:        now,
			MTime:        now,
			RFingerprint: key.RFingerprint,
			MD5:          key.MD5,
			Keywords:     keywords(key),
			Packets:      buf.Bytes(),
		}

		err = c.Insert(&doc)
		if err != nil {
			return errgo.Mask(err)
		}
		st.Notify(hkpstorage.KeyAdded{
			Digest: key.MD5,
		})
	}

	return nil
}

func (st *storage) Update(key *openpgp.Pubkey, lastMD5 string) error {
	openpgp.Sort(key)

	var buf bytes.Buffer
	err := openpgp.WritePackets(&buf, key)
	if err != nil {
		return errgo.Mask(err)
	}

	now := time.Now().Unix()
	update := bson.D{{"$set", bson.D{
		{"mtime", now},
		{"md5", key.MD5},
		{"keywords", keywords(key)},
		{"packets", buf.Bytes()},
	}}}

	session, c := st.c()
	defer session.Close()

	var doc keyDoc
	info, err := c.Find(bson.D{{"md5", lastMD5}}).Apply(mgo.Change{
		Update: update,
	}, &doc)
	if err != nil {
		return errgo.Mask(err)
	}
	if info.Updated == 0 {
		return errgo.Newf("failed to update md5=%q, didn't match lastMD5=%q",
			key.MD5, lastMD5)
	}

	st.Notify(hkpstorage.KeyReplaced{
		OldDigest: lastMD5,
		NewDigest: key.MD5,
	})
	return nil
}

// keywords returns a slice of searchable tokens extracted
// from the given UserID packet keywords string.
func keywords(key *openpgp.Pubkey) []string {
	m := make(map[string]bool)
	for _, uid := range key.UserIDs {
		s := strings.ToLower(uid.Keywords)
		lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
		if lbr != -1 && rbr > lbr {
			m[s[lbr+1:rbr]] = true
		}
		if lbr != -1 {
			fields := strings.FieldsFunc(s[:lbr], func(r rune) bool {
				if !utf8.ValidRune(r) {
					return true
				}
				if unicode.IsLetter(r) || unicode.IsNumber(r) {
					return false
				}
				return true
			})
			for _, field := range fields {
				m[field] = true
			}
		}
	}
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}

func (st *storage) Subscribe(f func(hkpstorage.KeyChange) error) {
	st.mu.Lock()
	st.listeners = append(st.listeners, f)
	st.mu.Unlock()
}

func (st *storage) Notify(change hkpstorage.KeyChange) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, f := range st.listeners {
		// TODO: log error notifying listener?
		f(change)
	}
	return nil
}
