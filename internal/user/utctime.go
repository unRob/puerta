// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package user

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/upper/db/v4"
)

type UTCTime struct {
	src  string
	time time.Time
}

var _ sql.Scanner = &UTCTime{}
var _ db.Marshaler = &UTCTime{}
var _ json.Marshaler = &UTCTime{}
var _ json.Unmarshaler = &UTCTime{}

func (t *UTCTime) Parse() (err error) {
	if t.src == "" {
		return fmt.Errorf("could not parse empty ttl")
	}

	t.time, err = time.Parse(time.RFC3339, t.src)
	return
}

func (t *UTCTime) Scan(value any) error {
	if value == nil {
		return nil
	}

	var ok bool
	if t.src, ok = value.(string); !ok {
		if err := json.Unmarshal(value.([]byte), &t.src); err != nil {
			return err
		}
	}

	if t.src == "" {
		return nil
	}

	if err := t.Parse(); err != nil {
		return err
	}

	return nil
}

func (t *UTCTime) Before(other time.Time) bool {
	return t.time.Before(other)
}

func (t *UTCTime) UnmarshalJSON(value []byte) error {
	if err := json.Unmarshal(value, &t.src); err != nil {
		return err
	}
	return t.Parse()
}

func (t *UTCTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.time.UTC().Format(time.RFC3339))
}

func (t *UTCTime) MarshalDB() (any, error) {
	return t.MarshalJSON()
}
