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
