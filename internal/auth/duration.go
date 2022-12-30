// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package auth

import (
	"fmt"
	"strconv"
	"time"
)

type Duration time.Duration

func (d Duration) MarshalDB() (any, error) {
	return time.Duration(d).String(), nil
}

func (d *Duration) UnmarshalDB(value any) error {
	str := value.(string)
	suffix := str[len(str)-1]

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
			return fmt.Errorf("unknown suffix for time duration %s", string(suffix))
		}

		str = str[0 : len(str)-1]
		days, err := strconv.Atoi(str)
		if err != nil {
			return err
		}

		str = fmt.Sprintf("%dh", days*multiplier)
	}
	tmp, err := time.ParseDuration(str)
	if err != nil {
		return err
	}
	*d = Duration(tmp)
	return nil
}

func (d *Duration) FromNow() time.Time {
	return time.Now().Add(time.Duration(*d))
}

func (d *Duration) Seconds() int {
	return int(time.Duration(*d).Seconds())
}
