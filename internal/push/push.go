package push

import (
	"git.rob.mx/nidito/puerta/internal/user"
	webpush "github.com/SherClockHolmes/webpush-go"
)

type VAPIDKey struct {
	Private string
	Public  string
}

type Config struct {
	Key *VAPIDKey
}

type Notifier struct {
	cfg *Config
}

var self *Notifier

func Notify(message string, subscriber *user.Subscription) error {
	resp, err := webpush.SendNotification([]byte(message), subscriber.AsWebPush(), &webpush.Options{
		Subscriber:      subscriber.ID(),
		VAPIDPublicKey:  self.cfg.Key.Public,
		VAPIDPrivateKey: self.cfg.Key.Private,
		TTL:             30,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func Initialize(cfg *Config) {
	self = &Notifier{cfg}
}
