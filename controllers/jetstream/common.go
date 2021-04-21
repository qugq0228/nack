// Copyright 2020 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jetstream

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	apis "github.com/nats-io/nack/pkg/jetstream/apis/jetstream/v1beta1"
	"github.com/nats-io/nats.go"
)

// AddAuthToOptions return nats options and error
func AddAuthToOptions(source interface{}, opts []nats.Option) ([]nats.Option, error) {
	var (
		credsSource string
		nkeySource  string
	)
	if o, ok := source.(Options); ok {
		credsSource = o.NATSCredentials
		nkeySource = o.NATSNKey
	} else if s, ok := source.(apis.ServerSpec); ok {
		credsSource = s.Creds
		nkeySource = s.Nkey
	} else {
		return opts, fmt.Errorf("unknown type: %v", source)
	}

	if credsSource != "" {
		credsFile, err := AuthTool(credsSource, "creds")
		if err != nil {
			return opts, err
		}
		opts = append(opts, nats.UserCredentials(credsFile))
	} else if nkeySource != "" {
		nkeyFile, err := AuthTool(nkeySource, "nkey")
		if err != nil {
			return opts, err
		}
		opt, err := nats.NkeyOptionFromSeed(nkeyFile)
		if err != nil {
			return opts, nil
		}
		opts = append(opts, opt)
	}
	return opts, nil
}

// AuthTool return a auth file path.
func AuthTool(auth, authType string) (string, error) {
	var (
		contents []byte
		filepath string
		fileType string
		basePath string
	)
	checkFileIsExist := func(filename string) bool {
		_, err := os.Stat(filename)
		return err == nil
	}

	if checkFileIsExist(auth) {
		return auth, nil
	}

	if authType == "creds" {
		fileType = ".creds"
		basePath = "/nack-accounts/creds/"
	} else if authType == "nkey" {
		fileType = ".nk"
		basePath = "/nack-accounts/keys/"
	} else {
		return "", fmt.Errorf("unknown auth type: %s", authType)
	}

	p := strings.SplitN(auth, ":", 2)
	if len(p) < 2 {
		return "", fmt.Errorf("not supported auth or file not exist: %s", auth)
	}
	lowerP0 := strings.ToLower(strings.TrimSpace(p[0]))
	if lowerP0 == authType {
		// Replace "\n" with a newline character
		contents = []byte(strings.ReplaceAll(strings.TrimSpace(p[1]), "\\n", string(byte(10))))
	} else if lowerP0 == "base64" {
		base := strings.TrimSpace(p[1])
		var err error
		contents, err = base64.StdEncoding.DecodeString(base)
		if err != nil {
			return "", err
		}
	}

	filepath = fmt.Sprintf("%s%x%s", basePath, md5.Sum(contents), fileType)
	if !checkFileIsExist(filepath) {
		err := os.MkdirAll(basePath, 0666)
		if err != nil {
			return "", err
		}
		err = ioutil.WriteFile(filepath, contents, 0666)
		if err != nil {
			return "", err
		}
		fmt.Println("cache to new file:", filepath)
	}
	return filepath, nil
}
