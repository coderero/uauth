package cache

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/coderero/paas-project/api/models"
	"github.com/coderero/paas-project/internal/utils"
	"github.com/redis/go-redis/v9"
)

type UserCache interface {
	// Set sets the user in the cache
	Set(user *models.User) error

	// Get gets the user from the cache
	Get(id int) (*models.User, error)

	// Delete deletes the user from the cache
	Delete(id int) error

	// SetDeletedUser sets the deleted user in the cache
	SetDeletedUser(sub string) error

	// GetDeletedUser gets the deleted user from the cache
	GetDeletedUser(sub string) (bool, error)

	// RemoveDeletedUser removes the deleted user from the cache
	RemoveDeletedUser(sub string) error

	// SetInactiveUser sets the inactive user in the cache
	SetInactiveUser(sub string) error

	// GetInactiveUser gets the inactive user from the cache
	GetInactiveUser(sub string) (bool, error)

	// RemoveInactiveUser removes the inactive user from the cache
	RemoveInactiveUser(sub string) error
}

// userCache is the implementation of the UserCache interface
type userCache struct {
	client *redis.Client
}

// NewUserCache creates a new user cache
func NewUserCache(client *redis.Client) UserCache {
	return &userCache{
		client: client,
	}
}

func (u *userCache) Set(user *models.User) error {
	usr, err := json.Marshal(user)
	if err != nil {
		return err
	}

	err = u.client.Set(context.Background(), strconv.Itoa(user.ID), usr, time.Hour*168).Err()
	return err
}

func (u *userCache) Get(id int) (*models.User, error) {
	user, err := u.client.Get(context.Background(), strconv.Itoa(id)).Result()
	if err != nil {
		return nil, err
	}

	var usr models.User
	err = json.Unmarshal([]byte(user), &usr)
	if err != nil {
		return nil, err
	}

	return &usr, nil
}

func (u *userCache) Delete(id int) error {
	return u.client.Del(context.Background(), strconv.Itoa(id)).Err()
}

func (u *userCache) SetDeletedUser(sub string) error {
	err := u.client.ZAdd(context.Background(), "deleted_users", redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: sub,
	}).Err()
	return err
}

func (u *userCache) GetDeletedUser(sub string) (bool, error) {
	scores, err := u.client.ZRevRange(context.Background(), "deleted_users", 0, -1).Result()
	if err != nil {
		return false, err
	}

	sort.Strings(scores)

	return utils.BinarySearch(scores, sub) == -1, nil
}

func (u *userCache) RemoveDeletedUser(sub string) error {
	return u.client.ZRem(context.Background(), "deleted_users", sub).Err()
}

func (u *userCache) SetInactiveUser(sub string) error {
	err := u.client.ZAdd(context.Background(), "inactive_users", redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: sub,
	}).Err()
	return err
}

func (u *userCache) GetInactiveUser(sub string) (bool, error) {
	scores, err := u.client.ZRevRange(context.Background(), "inactive_users", 0, -1).Result()
	if err != nil {
		return false, err
	}

	sort.Strings(scores)

	return utils.BinarySearch(scores, sub) == -1, nil
}

func (u *userCache) RemoveInactiveUser(sub string) error {
	return u.client.ZRem(context.Background(), "inactive_users", sub).Err()
}
