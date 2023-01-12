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

package service

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type Service struct {
	store *cache.Cache
}

const (
	defaultExpiration = 10 * time.Minute
	cleanupInterval   = 1 * time.Minute
)

func NewService() *Service {
	s := &Service{
		store: cache.New(defaultExpiration, cleanupInterval),
	}
	return s
}

func (s *Service) StoreCredential(req api.StoreCredentialRequest, resp *api.Credential) error {
	fmt.Println("Store", req.ID)
	if err := s.store.Add(req.ID, req.Credential, 10*time.Minute); err != nil {
		return err
	}
	*resp = *req.Credential
	return nil
}

func (s *Service) GetCredential(req api.GetCredentialRequest, resp *api.Credential) error {
	ctx := context.Background()
	fmt.Println("Get", req.ID)
	i, ok := s.store.Get(req.ID)
	if ok {
		fmt.Println("found cred!")
		cred, ok := i.(*api.Credential)
		if !ok {
			return fmt.Errorf("unknown credential type %T", i)
		}
		*resp = *cred
		return nil
	}

	if req.Config == nil {
		// No config set, nothing to do.
		return fmt.Errorf("%q not found", req.ID)
	}

	// If nothing is in the cache, fallback to interactive flow.
	fmt.Println("no cred found, going through intereractive flow...")
	idf := fulcio.NewIdentityFactory(os.Stdin, os.Stdout)
	id, err := idf.NewIdentity(ctx, req.Config)
	if err != nil {
		return fmt.Errorf("error getting new identity: %w", err)
	}
	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(id.PrivateKey)
	if err != nil {
		return err
	}
	cred := &api.Credential{
		PrivateKey: privPEM,
		Cert:       id.CertPEM,
		Chain:      id.ChainPEM,
	}
	if err := s.store.Add(req.ID, cred, 10*time.Minute); err != nil {
		// We still generated the credential just fine, so only log the error.
		fmt.Printf("error storing credential: %v\n", err)
	}
	*resp = *cred
	return nil
}
