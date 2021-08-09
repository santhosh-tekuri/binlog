package binlog

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRemote_Authenticate(t *testing.T) {
	if *mysql == "" {
		t.Skip(skipReason)
	}
	r, err := Dial(network, address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ssl {
		if !r.IsSSLSupported() {
			t.Fatal("server does not support ssl")
		}
		if err := r.UpgradeSSL(nil); err != nil {
			t.Fatal(err)
		}
	}
	err = r.Authenticate(user, passwd)
	t.Log("authFlow:", r.authFlow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.queryRows("show databases"); err != nil {
		t.Fatal(err)
	}
}

// test flags ---

var (
	mysql            = flag.String("mysql", "", "mysql server used for testing")
	network, address string
	user, passwd     string
	db               = "binlog"
	ssl              bool
	driverURL        string

	skipReason = `SKIPPED: pass -mysql flag to run this test
example: go test -mysql tcp:localhost:3306,ssl,user=root,password=password,db=binlog
`
)

func TestMain(m *testing.M) {
	flag.Parse()
	if *mysql != "" {
		colon := strings.IndexByte(*mysql, ':')
		network, address = (*mysql)[:colon], (*mysql)[colon+1:]
		tok := strings.Split(address, ",")
		address = tok[0]
		for _, t := range tok[1:] {
			switch {
			case t == "ssl":
				ssl = true
			case strings.HasPrefix(t, "user="):
				user = strings.TrimPrefix(t, "user=")
			case strings.HasPrefix(t, "password="):
				passwd = strings.TrimPrefix(t, "password=")
			case strings.HasPrefix(t, "db="):
				db = strings.TrimPrefix(t, "db=")
			}
		}
		tls := "false"
		if ssl {
			tls = "skip-verify"
		}
		timezone := url.QueryEscape(time.Now().Format("'-07:00'"))
		driverURL = fmt.Sprintf("%s:%s@%s(%s)/%s?tls=%v&time_zone=%s", user, passwd, network, address, db, tls, timezone)
	}
	os.Exit(m.Run())
}
