package services

import (
	"errors"

	"github.com/coderero/paas-project/api/models"
	"github.com/coderero/paas-project/internal/database"
)

var (
	ErrInvalidPermission = errors.New("invalid permission")
)

type UserService interface {
	// GetByID returns a user by its ID.
	GetByID(id int) (*models.User, error)

	// GetByUsername returns a user by its username.
	GetByUsername(username string) (*models.User, error)

	// GetByEmail returns a user by its email.
	GetByEmail(email string) (*models.User, error)

	// GetAllActive returns all active users.
	GetAllActive(string, int, int) ([]*models.User, error)

	// GetAllInactive returns all inactive users.
	GetAllInactive(string, int, int) ([]*models.User, error)

	// GetAll returns all users.
	GetAll(string, int, int) ([]*models.User, error)

	// Update updates a user.
	Update(user *models.User) error
	// SoftDelete soft deletes a user.
	SoftDelete(id int) error

	// HardDelete hard deletes a user.
	HardDelete(id int) error
}

type userServicer struct {
	userRepo database.UserRepository
}

func NewUserService(userRepo database.UserRepository) UserService {
	return &userServicer{
		userRepo: userRepo,
	}
}

func (u *userServicer) GetByID(id int) (*models.User, error) {
	return u.userRepo.GetUser(id)
}

func (u *userServicer) GetByUsername(username string) (*models.User, error) {
	return u.userRepo.GetUserByUsername(username)
}

func (u *userServicer) GetByEmail(email string) (*models.User, error) {
	return u.userRepo.GetUserByEmail(email)
}

func (u *userServicer) GetAllActive(permission string, page, limit int) ([]*models.User, error) {
	if permission != "admin" && permission != "superadmin" {
		return nil, ErrInvalidPermission
	}

	return u.userRepo.GetUsers(page, limit, database.OptionalArgs{Active: true, Admin: permission == "admin" || permission == "superadmin", Superadmin: permission == "superadmin"})
}

func (u *userServicer) GetAllInactive(permission string, page, limit int) ([]*models.User, error) {
	if permission != "admin" && permission != "superadmin" {
		return nil, ErrInvalidPermission
	}

	return u.userRepo.GetUsers(page, limit, database.OptionalArgs{Active: false, Admin: permission == "admin" || permission == "superadmin", Superadmin: permission == "superadmin"})
}

func (u *userServicer) GetAll(permission string, page, limit int) ([]*models.User, error) {
	if permission != "admin" && permission != "superadmin" {
		return nil, ErrInvalidPermission
	}

	return u.userRepo.GetUsers(page, limit, database.OptionalArgs{Admin: permission == "admin" || permission == "superadmin", Superadmin: permission == "superadmin"})
}

func (u *userServicer) Update(user *models.User) error {
	return u.userRepo.UpdateUser(user)
}

func (u *userServicer) SoftDelete(id int) error {
	return u.userRepo.DeleteUser(id)
}

func (u *userServicer) HardDelete(id int) error {
	return u.userRepo.HardDeleteUser(id)
}
