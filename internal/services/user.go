package services

import (
	"context"
	"database/sql"
	"errors"

	"github.com/coderero/paas-project/api/models"
	"github.com/coderero/paas-project/internal/database"
	"golang.org/x/sync/errgroup"
)

var (
	ErrInvalidPermission = errors.New("invalid permission")
)

type UserService interface {
	// Create creates a new user.
	Create(user *models.User) (int, error)

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

	// GetAllDeleted returns all deleted users.
	GetAllDeleted(string, int, int) ([]*models.User, error)

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
	userRepo     database.UserRepository
	cryptService CryptService
}

func NewUserService(userRepo database.UserRepository, cryptService CryptService) UserService {
	return &userServicer{
		userRepo:     userRepo,
		cryptService: cryptService,
	}
}

func (u *userServicer) Create(user *models.User) (int, error) {
	g, _ := errgroup.WithContext(context.Background())
	var usernameExists, emailExists bool
	g.Go(func() error {
		_, err := u.userRepo.GetUserByUsername(user.Username)
		if !errors.Is(err, sql.ErrNoRows) {
			usernameExists = true
		}

		return err
	})
	g.Go(func() error {
		_, err := u.userRepo.GetUserByEmail(user.Email)
		if !errors.Is(err, sql.ErrNoRows) {
			emailExists = true
		}

		return err
	})

	if err := g.Wait(); err != nil {
		return 0, err
	}

	if usernameExists && emailExists {
		return 0, ErrUserAlreadyExists
	}

	hashedPassword, err := u.cryptService.Hash(user.Password)
	if err != nil {
		return 0, err
	}

	user.Password = hashedPassword
	return u.userRepo.CreateUser(user)
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

func (u *userServicer) GetAllDeleted(permission string, page, limit int) ([]*models.User, error) {
	if permission != "admin" && permission != "superadmin" {
		return nil, ErrInvalidPermission
	}

	return u.userRepo.GetUsers(page, limit, database.OptionalArgs{Deleted: true, Admin: permission == "admin" || permission == "superadmin", Superadmin: permission == "superadmin"})
}

func (u *userServicer) GetAll(permission string, page, limit int) ([]*models.User, error) {
	if permission != "admin" && permission != "superadmin" {
		return nil, ErrInvalidPermission
	}

	return u.userRepo.GetUsers(page, limit, database.OptionalArgs{Admin: permission == "admin" || permission == "superadmin", Superadmin: permission == "superadmin", Active: true, Deleted: true})
}

func (u *userServicer) Update(user *models.User) error {
	g, _ := errgroup.WithContext(context.Background())
	var usernameExists, emailExists bool
	g.Go(func() error {
		_, err := u.userRepo.GetUserByUsername(user.Username)
		if !errors.Is(err, sql.ErrNoRows) {
			usernameExists = true
		}

		return err
	})
	g.Go(func() error {
		_, err := u.userRepo.GetUserByEmail(user.Email)
		if !errors.Is(err, sql.ErrNoRows) {
			emailExists = true
		}

		return err
	})

	if err := g.Wait(); err != nil {
		return err
	}

	if usernameExists && emailExists {
		return ErrUserAlreadyExists
	}

	return u.userRepo.UpdateUser(user)
}

func (u *userServicer) SoftDelete(id int) error {
	return u.userRepo.DeleteUser(id)
}

func (u *userServicer) HardDelete(id int) error {
	return u.userRepo.HardDeleteUser(id)
}
