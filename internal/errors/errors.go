// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package errors

type HTTPError interface {
	Error() string
	Code() int
}

func ToHTTP(err error) (string, int) {
	if err := err.(HTTPError); err != nil {
		return err.Error(), err.Code()
	}
	return err.Error(), 500
}
