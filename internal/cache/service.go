package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	cachepb "github.com/sigstore/gitsign/internal/cache/cache_go_proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	cachepb.UnimplementedCredentialStoreServer
	store *cache.Cache
}

func NewService() *Service {
	return &Service{
		store: cache.New(10*time.Minute, 1*time.Minute),
	}
}

func (s *Service) StoreCredential(ctx context.Context, req *cachepb.StoreCredentialRequest) (*cachepb.StoreCredentialResponse, error) {
	fmt.Println("Store", req.GetId())
	if err := s.store.Add(req.GetId(), req.GetCredential(), 10*time.Minute); err != nil {
		return nil, err
	}
	return &cachepb.StoreCredentialResponse{}, nil
}

func (s *Service) GetCredential(ctx context.Context, req *cachepb.GetCredentialRequest) (*cachepb.Credential, error) {
	fmt.Println("Get", req.GetId())
	i, ok := s.store.Get(req.GetId())
	if !ok {
		return nil, status.Errorf(codes.NotFound, "%q not found", req.GetId())
	}
	cred, ok := i.(*cachepb.Credential)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "found unexpected cache type %T", i)
	}
	return cred, nil
}
