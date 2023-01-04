# la puerta de mi casa

A ridiculously elaborate rubegoldbergian contraption to exchange my guests' biometric data for my front door going _bzzzz_, built with go, css, html and javascript.

This project is:

- **highly insecure**: you should not run this at home,
- **very alpha**: to put it mildly,
- **poorly tested** by my guests and myself, so barely—if at all, and
- **truly magical** to see in action, when it does work.

## Web App

This is what my guests see. It's basically a login page where they enter credentials, and then a big button to open the door. My guests are required to authenticate with a [_passkeys_](https://passkey.org/) before opening the door, usually backed by a yubikey, TouchID or whatever android does.

A very simple admin page allows me to manage guests and see the entry log. Built with pochjs (plain-old css, html and js).

## API

The API runs [on my homelab](https://github.com/unRob/nidito/blob/main/services/puerta/puerta.nomad), serves the web app and interacts with my front door's buzzer. It's built with go and backed by SQLite.

### Adapters

Since the buzzer electrical setup is still not something i completely understand, I went around the issue by connecting the buzzer's power supply to a "smart" plug. Originally built it to control a [wemo mini smart plug](https://www.belkin.com/support-article/?articleNum=226110), but have since switched into using a [hue one](https://www.philips-hue.com/en-us/p/hue-smart-plug/046677552343) for no good reason other than the wemo's API is annoying.

## CLI

There's a small CLI tool to start the API, setup and test the Hue connection, and to add users (helpful during bootstrap).
