// SPDX-License-Identifier: Apache-2.0
// Copyright © 2022 Roberto Hidalgo <nidito@un.rob.mx>
package door

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func init() {
	_register("wemo", NewWemo)
}

type Wemo struct {
	endpoint string
	client   *http.Client
}

func NewWemo(config map[string]any) Door {
	logrus.Infof("Wemo client for %s starting", config["endpoint"])
	return &Wemo{
		endpoint: config["endpoint"].(string),
		client:   &http.Client{Timeout: 4 * time.Second},
	}
}

const wemoBodyGet string = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetBinaryState xmlns:u="urn:Belkin:service:basicevent:1">
    </u:GetBinaryState>
  </s:Body>
</s:Envelope>`

const wemoBodySetTemplate string = `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:SetBinaryState xmlns:u="urn:Belkin:service:basicevent:1">
      <BinaryState>%s</BinaryState>
    </u:SetBinaryState>
  </s:Body>
</s:Envelope>`

func (wm *Wemo) request(op string, xml string) (string, error) {
	logrus.Debugf("requesting %s with body len %d\n", op, len(xml))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body := bytes.NewBufferString(xml)
	url := fmt.Sprintf("http://%s:49153/upnp/control/basicevent1", wm.endpoint)
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		logrus.Errorf("Failed creating http request to wemo: %s", err)
		return "", err
	}

	opHeader := fmt.Sprintf(`"urn:Belkin:service:basicevent:1#%s"`, op)
	req.Header.Set("content-type", `text/xml; charset="utf-8"`)
	req.Header.Set("content-length", fmt.Sprintf("%d", req.ContentLength))
	req.Header.Set("user-agent", "puerta.nidi.to")
	req.Header.Set("accept", "*/*")
	req.Header.Set("soapaction", opHeader)

	dump, _ := httputil.DumpRequest(req, true)
	logrus.Debugf("%s\n%s", string(dump), xml)

	res, err := wm.client.Do(req)
	if err != nil {
		return "", err
	}

	if res.StatusCode > 299 {
		return "", fmt.Errorf("%s Request failed with code %d", op, res.StatusCode)
	}

	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(bodyBytes), err
}

func (wm *Wemo) IsOpen() (bool, error) {
	statusBody, err := wm.request("GetBinaryState", wemoBodyGet)
	if err != nil {
		return false, err
	}

	if strings.Contains(statusBody, "<BinaryState>0</BinaryState>") {
		return false, nil
	} else if strings.Contains(statusBody, "<BinaryState>1</BinaryState>") {
		return true, nil
	}

	return false, fmt.Errorf("unknown response from wemo: %s", statusBody)
}

func (wm *Wemo) Open(errors chan<- error, done chan<- bool) {
	defer close(errors)
	defer close(done)
	if _, err := wm.request("SetBinaryState", fmt.Sprintf(wemoBodySetTemplate, "1")); err != nil {
		errors <- err
		return
	}

	errors <- nil

	time.Sleep(4 * time.Second)

	if _, err := wm.request("SetBinaryState", fmt.Sprintf(wemoBodySetTemplate, "0")); err != nil {
		errors <- err
		return
	}

	done <- true
}

func (wm *Wemo) Close(errors chan error) {
	err, ok := <-errors
	if ok && err != nil {
		logrus.Errorf("Failed during power off: %s", err)
		return
	} else if ok {
		logrus.Info("Door power shut off correctly")
	}
}
