// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
)

type Service struct {
	store *cache.Cache
}

func NewService() *Service {
	s := &Service{
		store: cache.New(10*time.Minute, 1*time.Minute),
	}
	return s
}

type Credential struct {
	PrivateKey []byte
	Cert       []byte
	Chain      []byte
}

type StoreCredentialRequest struct {
	ID         string
	Credential *Credential
}

func (s *Service) StoreCredential(req StoreCredentialRequest, resp *Credential) error {
	fmt.Println("Get", req.ID)
	if err := s.store.Add(req.ID, req.Credential, 10*time.Minute); err != nil {
		return err
	}
	*resp = *req.Credential
	return nil
}

type GetCredentialRequest struct {
	ID string
}

func (s *Service) GetCredential(req GetCredentialRequest, resp *Credential) error {
	fmt.Println("Get", req.ID)
	i, ok := s.store.Get(req.ID)
	if !ok {
		return fmt.Errorf("%q not found", req.ID)
	}
	cred, ok := i.(*Credential)
	if !ok {
		return fmt.Errorf("unknown credential type %T", i)

	}
	*resp = *cred
	return nil
}
