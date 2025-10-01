package cache

import (
	"context"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
)

type JwtCache interface {
	// Revoke revokes the token
	Revoke(context.Context, string, string) error

	// IsRevoked returns true if the token
	IsRevoked(context.Context, string, string) bool
}

// jwtCache is the implementation of the JwtCache interface
type jwtCache struct {
	client *redis.Client
}

// NewJwtCache creates a new jwt cache
func NewJwtCache(client *redis.Client) JwtCache {
	return &jwtCache{
		client: client,
	}
}

func (j *jwtCache) Revoke(ctx context.Context, sub, token string) error {
	err := j.client.ZAdd(ctx, sub, redis.Z{Score: float64(time.Now().Unix()), Member: token}).Err()
	if err != nil {
		return err
	}

	return j.client.Expire(ctx, sub, time.Hour*168).Err()
}

func (j *jwtCache) IsRevoked(ctx context.Context, sub, token string) bool {
	score, err := j.client.ZRevRange(ctx, sub, 0, -1).Result()
	if err != nil {
		return false
	}

	sort.Strings(score)
	return sort.SearchStrings(score, token) != -1
}
