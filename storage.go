package mongo

import (
	"bytes"
	"strings"
	"time"

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
}

func NewStorage(session *mgo.Session) (*storage, error) {
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

	var regexes []string
	for _, keyid := range keyids {
		if len(keyid) < maxFingerprintLen {
			regexes = append(regexes, "/^"+keyid+"/")
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

	for i := range keywords {
		keywords[i] = strings.ToLower(keywords[i])
	}

	var result []string
	var doc keyDoc

	iter := c.Find(bson.D{{"keywords", bson.D{{"$elemMatch", bson.D{{"$in", keywords}}}}}}).Limit(100).Iter()
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
	var docs []interface{}
	for _, key := range keys {
		doc := &keyDoc{}
		now := time.Now()
		doc.CTime = now.Unix()
		doc.MTime = now.Unix()
		doc.RFingerprint = key.RFingerprint
		doc.MD5 = key.MD5
		doc.Keywords = keywords(key)
		docs = append(docs, doc)
	}
	session, c := st.c()
	defer session.Close()

	return c.Insert(docs...)
}

func (st *storage) Update(key *openpgp.Pubkey, lastMD5 string) error {
	panic("TODO")
}

func keywords(key *openpgp.Pubkey) []string {
	panic("TODO")
}

func (st *storage) Subscribe(func(hkpstorage.KeyChange) error) {
	panic("TODO")
}

func (st *storage) Notify(change hkpstorage.KeyChange) error {
	panic("TODO")
}
