package main

import (
	"binlog"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type binLog interface {
	ListFiles() ([]string, error)
	MasterStatus() (file string, pos uint32, err error)
	Seek(serverID uint32, fileName string, position uint32) error
	NextEvent() (binlog.Event, error)
	NextRow() (values []interface{}, valuesBeforeUpdate []interface{}, err error)
}

// binlog view tcp:localhost:3306,ssl,user=root,passwd=password binlog.000002:4
// binlog view dir:/Users/santhosh/go/src/binlog/dump binlog.000002
// binlog dump tcp:localhost:3306,ssl,user=root,passwd=password /Users/santhosh/go/src/binlog/dump
func main() {
	address := os.Args[2]
	colon := strings.IndexByte(address, ':')
	network, address := address[:colon], address[colon+1:]
	switch os.Args[1] {
	case "view":
		var bl binLog
		if network == "dir" {
			bl = openLocal(address)
		} else {
			bl = openRemote(network, address)
		}
		file, pos := getLocation(bl, os.Args[3])
		if err := bl.Seek(10, file, pos); err != nil {
			panic(err)
		}
		if err := view(bl); err != nil {
			panic(err)
		}
	case "dump":
		remote := openRemote(network, address)
		dir := os.Args[3]
		var file string
		var pos uint32
		local := openLocal(dir)
		file, pos, err := local.MasterStatus()
		if err != nil {
			panic(err)
		}
		if file == "" {
			files, err := remote.ListFiles()
			if err != nil {
				panic(err)
			}
			file, pos = files[0], 4
		}
		fmt.Printf("dumping from %s:0x%02x\n", file, pos)
		if err := remote.Seek(0, file, pos); err != nil {
			panic(err)
		}
		if err := remote.Dump(dir); err != nil && err != io.EOF {
			panic(err)
		}
	}
}

func openRemote(network, address string) *binlog.Remote {
	tok := strings.Split(address, ",")
	bl, err := binlog.Dial(network, tok[0])
	if err != nil {
		panic(err)
	}
	if bl.IsSSLSupported() {
		for _, t := range tok[1:] {
			if t == "ssl" {
				if err = bl.UpgradeSSL(nil); err != nil {
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
	if err := bl.SetHeartbeatPeriod(30 * time.Second); err != nil {
		panic(err)
	}
	return bl
}

func getLocation(bl binLog, arg string) (file string, pos uint32) {
	switch arg {
	case "earliest":
		files, err := bl.ListFiles()
		if err != nil {
			panic(err)
		}
		return files[0], 4
	case "latest":
		file, pos, err := bl.MasterStatus()
		if err != nil {
			panic(err)
		}
		return file, pos
	default:
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
}

func openLocal(address string) *binlog.Local {
	bl, err := binlog.Open(address)
	if err != nil {
		panic(err)
	}
	return bl
}

func view(bl binLog) error {
	for {
		e, err := bl.NextEvent()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			panic(err)
		}
		fmt.Printf("%s %s:0x%04x %-17s",
			time.Unix(int64(e.Header.Timestamp), 0).Format("2006-01-02 15:04:05"),
			e.Header.LogFile,
			e.Header.NextPos,
			e.Header.EventType,
		)
		switch d := e.Data.(type) {
		case binlog.FormatDescriptionEvent:
			fmt.Print(" v", d.BinlogVersion, " ", d.ServerVersion)
		case binlog.TableMapEvent:
			fmt.Print(" ", d.SchemaName+"."+d.TableName)
		case binlog.RowsEvent:
			if d.TableMap != nil {
				fmt.Print(" ", d.TableMap.SchemaName+"."+d.TableMap.TableName)
			}
		}
		fmt.Println()
		if _, ok := e.Data.(binlog.RowsEvent); ok {
			for {
				row, before, err := bl.NextRow()
				if err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}
				fmt.Println("         ", row)
				if before != nil {
					fmt.Println("  before:", before)
				}
			}
		}
	}
}
