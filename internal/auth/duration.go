// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"fmt"
	"strconv"
	"time"
)

var DefaultTTL = TTL("30d")

type TTL string

func (ttl TTL) ToDuration() (res time.Duration, err error) {
	suffix := ttl[len(ttl)-1]

	toParse := string(ttl)
	if suffix == 'd' || suffix == 'w' || suffix == 'M' {
		multiplier := 1
		switch suffix {
		case 'd':
			multiplier = 24
		case 'w':
			multiplier = 24 * 7
		case 'M':
			multiplier = 24 * 7 * 30
		default:
			err = fmt.Errorf("unknown suffix for time duration %s", string(suffix))
			return
		}

		toParse = toParse[0 : len(toParse)-1]
		var days int
		days, err = strconv.Atoi(toParse)
		if err != nil {
			return
		}

		toParse = fmt.Sprintf("%dh", days*multiplier)
	}
	res, err = time.ParseDuration(toParse)
	return
}

func (ttl *TTL) FromNow() time.Time {
	d, _ := ttl.ToDuration()
	return time.Now().Add(d)
}

func (ttl *TTL) Seconds() int {
	d, _ := ttl.ToDuration()
	return int(d.Seconds())
}

// var _ = (db.Unmarshaler(&TTL{}))
// var _ = (db.Marshaler(&TTL{}))
