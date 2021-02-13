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

func printUsage() {
	errln("Usage:")
	errln()
	errln("binlog view ADDRESS SERVER-ID LOCATION")
	errln("Arguments:")
	errln("    SERVER-ID   optional. defaults to 0. non-zero will wait for new events.")
	errln("    LOCATION    optional. valid values are earliest, latest or FILE[:POS].")
	errln("                defaults to earliest. POS defaults to 4.")
	errln("Examples:")
	errln("    binlog view tcp:localhost:3306,ssl,user=root,password=password 10 binlog.000002:4")
	errln("    binlog view dir:./dump 10 binlog.000002")
	errln()
	errln("binlog dump SERVER-URL DIR SERVER-ID FROM-FILE")
	errln("Arguments:")
	errln("    SERVER-ID   optional. defaults to 0. non-zero will wait for new events.")
	errln("    FROM-FILE   optional. valid values are earliest, latest or binlog-filename.")
	errln("                defaults to earliest. used only if DIR is empty, otherwise")
	errln("                resumes since last location.")
	errln("Examples:")
	errln("    binlog dump tcp:localhost:3306,ssl,user=root,password=password ./dump 10 binlog.000001")
}

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}
	address := os.Args[2]
	colon := strings.IndexByte(address, ':')
	network, address := address[:colon], address[colon+1:]
	var err error
	switch os.Args[1] {
	case "view":
		var bl binLog
		if network == "dir" {
			bl = openLocal(address)
		} else {
			bl = openRemote(network, address)
		}
		var serverID = 0
		if len(os.Args) >= 4 {
			serverID, err = strconv.Atoi(os.Args[3])
			if err != nil {
				panic(err)
			}
		}
		var file string
		var pos uint32
		if len(os.Args) >= 5 {
			file, pos = getLocation(bl, os.Args[4])
		} else {
			files, err := bl.ListFiles()
			if err != nil {
				panic(err)
			}
			file, pos = files[0], 4
		}
		if err := bl.Seek(uint32(serverID), file, pos); err != nil {
			panic(err)
		}
		if err := view(bl); err != nil {
			panic(err)
		}
	case "dump":
		if len(os.Args) < 4 {
			printUsage()
			os.Exit(1)
		}
		remote := openRemote(network, address)
		dir := os.Args[3]
		var serverID = 0
		if len(os.Args) >= 5 {
			serverID, err = strconv.Atoi(os.Args[4])
			if err != nil {
				panic(err)
			}
		}
		local := openLocal(dir)
		file, pos, err := local.MasterStatus()
		if err != nil {
			panic(err)
		}
		if file == "" {
			if len(os.Args) > 5 {
				file, _ = getLocation(remote, os.Args[4])
				pos = 4
			} else {
				files, err := remote.ListFiles()
				if err != nil {
					panic(err)
				}
				file, pos = files[0], 4
			}
		}
		fmt.Printf("dumping from %s:0x%02x\n", file, pos)
		if err := remote.Seek(uint32(serverID), file, pos); err != nil {
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
		if strings.HasPrefix(t, "password=") {
			passwd = strings.TrimPrefix(t, "password=")
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
		off, err := strconv.ParseInt(arg[colon+1:], 0, 64)
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
		//fmt.Printf(" %#v\n", e.Data)
		switch d := e.Data.(type) {
		case binlog.FormatDescriptionEvent:
			fmt.Println(" ", "v"+strconv.Itoa(int(d.BinlogVersion)), d.ServerVersion)
		case binlog.TableMapEvent:
			fmt.Println(d.SchemaName + "." + d.TableName)
		case binlog.RowsEvent:
			if d.TableMap != nil {
				fmt.Print(d.TableMap.SchemaName + "." + d.TableMap.TableName)
			}
			fmt.Println()
			for {
				row, before, err := bl.NextRow()
				if err != nil {
					if err == io.EOF {
						break
					}
					panic(err)
				}
				if e.Header.EventType.IsDeleteRows() {
					fmt.Print("   WHERE:")
				} else {
					fmt.Print("     SET:")
				}
				for i, v := range row {
					col := d.Columns()[i].Name
					if col == "" {
						col = "@" + strconv.Itoa(d.Columns()[i].Ordinal)
					}
					fmt.Printf(" %s=%s", col, d.Columns()[i].ValueLiteral(v))
				}
				fmt.Println()
				if before != nil {
					fmt.Print("   WHERE:")
					for i, v := range before {
						col := d.ColumnsBeforeUpdate()[i].Name
						if col == "" {
							col = "@" + strconv.Itoa(d.ColumnsBeforeUpdate()[i].Ordinal)
						}
						fmt.Printf(" %s=%s", col, d.ColumnsBeforeUpdate()[i].ValueLiteral(v))
					}
					fmt.Println()
				}
			}
		default:
			fmt.Println()
		}
	}
}

func errln(args ...interface{}) {
	_, _ = fmt.Fprintln(os.Stderr, args...)
}
