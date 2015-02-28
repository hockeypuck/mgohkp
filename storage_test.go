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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	stdtesting "testing"

	"github.com/facebookgo/mgotest"
	"github.com/hockeypuck/testing"
	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"

	"gopkg.in/hockeypuck/hkp.v0"
	"gopkg.in/hockeypuck/openpgp.v0"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type MgoSuite struct {
	storage *storage
	mgoSrv  *mgotest.Server
	session *mgo.Session
	srv     *httptest.Server
}

var _ = gc.Suite(&MgoSuite{})

func (s *MgoSuite) SetUpTest(c *gc.C) {
	s.mgoSrv = mgotest.NewStartedServer(c)
	s.session = s.mgoSrv.Session()
	st, err := New(s.session)
	c.Assert(err, gc.IsNil)
	s.storage = st.(*storage)

	r := httprouter.New()
	handler := hkp.NewHandler(s.storage)
	handler.Register(r)
	s.srv = httptest.NewServer(r)
}

func (s *MgoSuite) TearDownTest(c *gc.C) {
	s.srv.Close()
	s.session.Close()
	s.mgoSrv.Stop()
}

func (s *MgoSuite) addKey(c *gc.C, keyname string) {
	keytext, err := ioutil.ReadAll(testing.MustInput(keyname))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	_, err = ioutil.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)
}

func (s *MgoSuite) TestMD5(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	s.addKey(c, "sksdigest.asc")
	session, coll := s.storage.c()
	defer session.Close()
	var doc keyDoc
	err = coll.Find(bson.D{{"md5", "da84f40d830a7be2a3c0b7f2e146bfaa"}}).One(&doc)
	c.Assert(err, gc.IsNil)

	res, err = http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	armor, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "ce353cf4")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Jenny Ondioline <jennyo@transient.net>")
}

func (s *MgoSuite) TestAddDuplicates(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	for i := 0; i < 10; i++ {
		s.addKey(c, "sksdigest.asc")
	}

	session, coll := s.storage.c()
	defer session.Close()
	n, err := coll.Find(bson.D{{"md5", "da84f40d830a7be2a3c0b7f2e146bfaa"}}).Count()
	c.Assert(err, gc.IsNil)
	c.Assert(n, gc.Equals, 1)
}

func (s *MgoSuite) TestResolve(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x44a2d1db")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	s.addKey(c, "uat.asc")
	var doc keyDoc
	session, coll := s.storage.c()
	defer session.Close()
	err = coll.Find(nil).One(&doc)
	c.Assert(err, gc.IsNil)

	// Should match
	for _, search := range []string{
		// short, long and full fingerprint key IDs match
		"0x44a2d1db", "0xf79362da44a2d1db", "0x81279eee7ec89fb781702adaf79362da44a2d1db",
		// contiguous words and email addresses match
		"casey", "marshall", "casey+marshall", "cAseY+MArSHaLL",
		"casey.marshall@gmail.com", "casey.marshall@gazzang.com"} {
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil)
		armor, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

		keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
		c.Assert(keys, gc.HasLen, 1)
		c.Assert(keys[0].ShortID(), gc.Equals, "44a2d1db")
		c.Assert(keys[0].UserIDs, gc.HasLen, 2)
		c.Assert(keys[0].UserAttributes, gc.HasLen, 1)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@gazzang.com>")
	}

	// Shouldn't match any of these
	for _, search := range []string{
		"0xdeadbeef", "0xce353cf4", "0xd1db", "44a2d1db", "0xadaf79362da44a2d1db",
		"alice@example.com", "bob@example.com", "marshal", "com"} {
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil)
		res.Body.Close()
		c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)
	}
}

func (s *MgoSuite) TestMerge(c *gc.C) {
	s.addKey(c, "alice_unsigned.asc")
	s.addKey(c, "alice_signed.asc")

	session, coll := s.storage.c()
	defer session.Close()
	n, err := coll.Find(nil).Count()
	c.Assert(err, gc.IsNil)
	c.Assert(n, gc.Equals, 1)

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=alice@example.com")
	c.Assert(err, gc.IsNil)
	armor, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "23e0dcca")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Signatures, gc.HasLen, 2)
}
