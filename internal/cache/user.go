package cache

import (
	"github.com/coderero/paas-project/api/models"
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
	return nil
}

func (u *userCache) Get(id int) (*models.User, error) {
	return nil, nil
}

func (u *userCache) Delete(id int) error {
	return nil
}

func (u *userCache) SetDeletedUser(sub string) error {
	return nil
}

func (u *userCache) GetDeletedUser(sub string) (bool, error) {
	return false, nil
}

func (u *userCache) RemoveDeletedUser(sub string) error {
	return nil
}

func (u *userCache) SetInactiveUser(sub string) error {
	return nil
}

func (u *userCache) GetInactiveUser(sub string) (bool, error) {
	return false, nil
}

func (u *userCache) RemoveInactiveUser(sub string) error {
	return nil
}
