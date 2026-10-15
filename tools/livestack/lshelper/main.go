// Command lshelper runs SQL against the livestack's Postgres, so the
// script needs no psql. Rows of the last statement are printed as JSON
// lines; UUIDs are printed in their canonical form.
//
//	lshelper <dsn> [sql]    (the SQL is read from stdin when not given)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: lshelper <dsn> [sql]")
		os.Exit(2)
	}
	if err := run(os.Args[1], strings.Join(os.Args[2:], " ")); err != nil {
		fmt.Fprintln(os.Stderr, "lshelper:", err)
		os.Exit(1)
	}
}

func run(dsn, q string) error {
	if q == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		q = string(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	// The simple protocol runs multi-statement scripts.
	rows, err := conn.Query(ctx, q, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(os.Stdout)
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return err
		}
		m := map[string]any{}
		for i, f := range rows.FieldDescriptions() {
			v := vals[i]
			if b, ok := v.([16]byte); ok {
				v = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
			}
			m[f.Name] = v
		}
		if err := enc.Encode(m); err != nil {
			return err
		}
	}
	return rows.Err()
}
