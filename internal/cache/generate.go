//go:generate protoc --go_out=cache_go_proto --go_opt=paths=source_relative --go-grpc_out=cache_go_proto --go-grpc_opt=paths=source_relative cache.proto
package cache
