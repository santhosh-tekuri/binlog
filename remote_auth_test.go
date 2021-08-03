package binlog

import (
	"testing"
)

func TestRemote_Authenticate(t *testing.T) {
	if *mysql == "" {
		t.Skip(`SKIPPED: pass -mysql flag to run this test
example: go test -mysql tcp:localhost:3306,ssl,user=root,password=password,db=binlog
`)
	}
	parseMySQLURL()
	testAuth(t)
}

func testAuth(t *testing.T) {
	r, err := Dial(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ssl && r.IsSSLSupported() {
		if err := r.UpgradeSSL(nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Authenticate(user, passwd); err != nil {
		t.Fatal(err)
	}
	if _, err = r.queryRows("show databases"); err != nil {
		t.Fatal(err)
	}
}
