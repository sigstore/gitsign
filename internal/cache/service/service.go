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

	gocache "github.com/patrickmn/go-cache"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/fulcio"
)

type Service struct {
	store *gocache.Cache
}

const (
	defaultExpiration = 10 * time.Minute
	cleanupInterval   = 1 * time.Minute
)

// record is what's stored per credential - the credential itself plus
// metadata for enumeration.
type record struct {
	Credential *api.Credential
	Info       api.CredentialInfo
}

func NewService() *Service {
	s := &Service{
		store: gocache.New(defaultExpiration, cleanupInterval),
	}
	return s
}

// store saves the credential with a TTL matching the certificate lifetime,
// overwriting any existing entry for the ID.
func (s *Service) storeCredential(id string, cred *api.Credential, meta api.Metadata) error {
	notAfter, err := cache.NotAfter(cred.Cert)
	if err != nil {
		return err
	}
	ttl := time.Until(notAfter)
	if ttl <= 0 {
		return fmt.Errorf("certificate is already expired (NotAfter: %s)", notAfter)
	}
	s.store.Set(id, &record{
		Credential: cred,
		Info: api.CredentialInfo{
			ID:       id,
			NotAfter: notAfter,
			Meta:     meta,
		},
	}, ttl)
	return nil
}

func (s *Service) StoreCredential(req api.StoreCredentialRequest, resp *api.Credential) error {
	fmt.Println("Store", req.ID)
	if err := s.storeCredential(req.ID, req.Credential, req.Meta); err != nil {
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
		fmt.Println("gitsign-credential-cache: found credential!")
		rec, ok := i.(*record)
		if !ok {
			return fmt.Errorf("unknown credential type %T", i)
		}
		*resp = *rec.Credential
		return nil
	}

	if req.Config == nil {
		// No config set, nothing to do.
		return fmt.Errorf("%q not found", req.ID)
	}

	// If nothing is in the cache, fallback to interactive flow.
	fmt.Println("gitsign-credential-cache: no cached credential found, falling back to interactive flow...")
	idf := fulcio.NewIdentityFactory(os.Stdin, os.Stdout)
	id, err := idf.NewIdentity(ctx, req.Config)
	if err != nil {
		return fmt.Errorf("error getting new identity: %w", err)
	}
	cred, err := cache.EncodeCredential(id.PrivateKey, id.CertPEM, id.ChainPEM)
	if err != nil {
		return err
	}
	if err := s.storeCredential(req.ID, cred, cache.MetadataFromConfig(req.Config)); err != nil {
		// We still generated the credential just fine, so only log the error.
		fmt.Printf("error storing credential: %v\n", err)
	}
	*resp = *cred
	return nil
}

func (s *Service) ListCredentials(_ api.ListCredentialsRequest, resp *[]api.CredentialInfo) error {
	fmt.Println("List")
	out := []api.CredentialInfo{}
	for _, item := range s.store.Items() {
		rec, ok := item.Object.(*record)
		if !ok {
			continue
		}
		out = append(out, rec.Info)
	}
	*resp = out
	return nil
}

func (s *Service) DeleteCredential(req api.DeleteCredentialRequest, _ *api.DeleteCredentialsResponse) error {
	fmt.Println("Delete", req.ID)
	if _, ok := s.store.Get(req.ID); !ok {
		return fmt.Errorf("%q not found", req.ID)
	}
	s.store.Delete(req.ID)
	return nil
}

func (s *Service) DeleteAllCredentials(_ api.DeleteAllCredentialsRequest, _ *api.DeleteCredentialsResponse) error {
	fmt.Println("DeleteAll")
	s.store.Flush()
	return nil
}
