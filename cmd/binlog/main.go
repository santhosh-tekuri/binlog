package main

import (
	"binlog"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type binLog interface {
	NextEvent() (binlog.Event, error)
	NextRow() ([][]interface{}, error)
}

// binlog view tcp:localhost:3306,ssl,user=root,passwd=password binlog.000002:4
// binlog view dir:/Users/santhosh/go/src/binlog/dump binlog.000002
// binlog dump tcp:localhost:3306,ssl,user=root,passwd=password /Users/santhosh/go/src/binlog/dump binlog.000001
func main() {
	switch os.Args[1] {
	case "view":
		address := os.Args[2]
		colon := strings.IndexByte(address, ':')
		network, address := address[:colon], address[colon+1:]
		var bl binLog
		if network == "dir" {
			bl = openLocal(address, os.Args[3])
		} else {
			bl = openRemote(network, address, os.Args[3])
		}
		if err := view(bl); err != nil {
			panic(err)
		}
	case "dump":
		address := os.Args[2]
		colon := strings.IndexByte(address, ':')
		network, address := address[:colon], address[colon+1:]
		bl := openRemote(network, address, os.Args[4])
		if err := bl.Dump(os.Args[3]); err != nil {
			panic(err)
		}
	}
}

func openRemote(network, address, location string) *binlog.Remote {
	tok := strings.Split(address, ",")
	bl, err := binlog.Dial(network, tok[0])
	if err != nil {
		panic(err)
	}
	if bl.IsSSLSupported() {
		for _, t := range tok[1:] {
			if t == "ssl" {
				if err = bl.UpgradeSSL(); err != nil {
					panic(err)
				}
				break
			}
		}
	}
	var user, passwd string
	for _, t := range tok[1:] {
		if strings.HasPrefix(t, "user=") {
			user = strings.TrimPrefix(t, "user=")
		}
		if strings.HasPrefix(t, "passwd=") {
			passwd = strings.TrimPrefix(t, "passwd=")
		}
	}
	if err := bl.Authenticate(user, passwd); err != nil {
		panic(err)
	}

	files, err := bl.ListFiles()
	if err != nil {
		panic(err)
	}
	fmt.Println("files:", files)

	file, pos, err := bl.MasterStatus()
	if err != nil {
		panic(err)
	}
	fmt.Printf("master status: %s:%d\n", file, pos)

	if err := bl.SetHeartbeatPeriod(5 * time.Second); err != nil {
		panic(err)
	}
	file, pos = getLocation(location)
	fmt.Println("file", file, pos)
	if err := bl.RequestBinlog(10, file, pos); err != nil {
		panic(err)
	}
	return bl
}

func openLocal(address, file string) *binlog.Local {
	bl, err := binlog.Open(path.Join(address, file))
	if err != nil {
		panic(err)
	}

	files, err := bl.ListFiles()
	if err != nil {
		panic(err)
	}
	fmt.Println("files:", files)

	return bl
}

func view(bl binLog) error {
	for {
		fmt.Println("-------------------------")
		e, err := bl.NextEvent()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%#v\n%#v\n", e.Header, e.Data)
		if _, ok := e.Data.(binlog.RowsEvent); ok {
			for {
				row, err := bl.NextRow()
				if err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}
				fmt.Println("        ", row)
			}
		}
	}
}

func getLocation(arg string) (file string, pos uint32) {
	colon := strings.IndexByte(arg, ':')
	if colon == -1 {
		return arg, 4
	}
	file = arg[:colon]
	off, err := strconv.Atoi(arg[colon+1:])
	if err != nil {
		panic(err)
	}
	return file, uint32(off)
}
