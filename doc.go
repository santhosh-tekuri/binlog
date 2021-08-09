/*
Package binlog implements mysql binlog replication protocol.

This library is mainly aimed to provide RBR event parsing.

to connect to mysql server:

	bl, err := binlog.Dial("tcp", "localhost:3306", 5*time.Second)
	if err != nil {
		return err
	}
	if bl.IsSSLSupported() {
		if err = bl.UpgradeSSL(tlsConfig); err != nil {
			return err
		}
	}
	if err := bl.Authenticate("root", "secret"); err != nil {
		return err
	}

to get binlog events from server:

	serverID := 0 // use non-zero to wait for more data after end of last log
	if serverID !=0 {
		// send heartbeatEvent when there is no more data
		if err := bl.SetHeartbeatPeriod(30 * time.Second); err != nil {
			return err
		}
	}
	if err := bl.Seek(serverID, "binlog.000001", 4); err != nil {
		return err
	}
	for {
		e, err := bl.NextEvent()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		re, ok := e.Data.(binlog.RowsEvent)
		if !ok {
			continue
		}
		fmt.Sprintf("Table: %s.%s\n", re.TableMap.SchemaName, re.TableMap.TableName)
		if e.IsWriteRows() {
			fmt.Println("Action: insert")
		else if e.IsUpdateRows() {
			fmt.Println("Action: update")
		else if e.IsDeleteRows() {
			fmt.Println("Action: delete")
		}
		for {
			row, _, err := bl.NextRow()
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			for i, v := range row {
				col := d.Columns()[i]
				fmt.Sprintf("col=%s ordinal=%d value=%v\n", col.Name, col.Ordinal, v)
			}
		}
	}

this package also supports the following:
	- dump to local directory
	- resume dump from where it left
	- read binlog files from dump directory as if it is server

for example usage see cmd/binlog/main.go
*/
package binlog
