package user

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/upper/db/v4"
)

type WPS struct {
	*webpush.Subscription
}

func (w *WPS) Scan(value any) error {
	if value == nil {
		return nil
	}

	sub := &webpush.Subscription{}
	if valueStr, ok := value.(string); ok {
		if err := json.Unmarshal([]byte(valueStr), &sub); err != nil {
			return fmt.Errorf("could not unmarshal str: %s, err: %s", valueStr, err)
		}
		w.Subscription = sub
	} else if valueList, ok := value.([]byte); ok {
		if err := json.Unmarshal(valueList, &sub); err != nil {
			return fmt.Errorf("could not unmarshal bytes: %s, err: %s", valueList, err)
		}
		w.Subscription = sub
	}

	return nil
}

func (w WPS) MarshalDB() (any, error) {
	return json.Marshal(w.Subscription)
}

func (w WPS) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.Subscription)
}

func (w *WPS) UnmarshalJSON(value []byte) error {
	sub := &webpush.Subscription{}
	if err := json.Unmarshal(value, &sub); err != nil {
		return err
	}
	w.Subscription = sub
	return nil
}

type Subscription struct {
	UserID int  `db:"user"`
	Data   *WPS `db:"data"`
}

func (s *Subscription) AsWebPush() *webpush.Subscription {
	return s.Data.Subscription
}

func (s *Subscription) ID() string {
	return fmt.Sprintf("user-%d@puerta.nidi.to", s.UserID)
}

func (s *Subscription) Store(sess db.Session) db.Store {
	return sess.Collection("subscription")
}

var _ sql.Scanner = &WPS{}
var _ db.Record = &Subscription{}
var _ db.Marshaler = &WPS{}
var _ json.Marshaler = &WPS{}
var _ json.Unmarshaler = &WPS{}
