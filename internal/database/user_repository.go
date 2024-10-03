package database

import (
	"database/sql"
	"net"

	"github.com/coderero/paas-project/api/models"
	"github.com/coderero/paas-project/internal/types"
	"github.com/coderero/paas-project/internal/utils"
)

type UserRepository interface {
	// CreateUser creates a new user with the given details.
	CreateUser(user *models.User) (int, error)

	// GetUser returns the user with the given ID.
	GetUser(id int) (*models.User, error)

	// GetUsers returns all users.
	GetUsers(optional *types.UserAccessFilter) ([]*models.User, error)

	// UpdateUser updates the user with the given ID.
	UpdateUser(user *models.User) error

	// DeleteUser deletes the user with the given ID.
	DeleteUser(id int) error

	// HardDeleteUser deletes the user with the given ID permanently.
	HardDeleteUser(id int) error

	// CreateAuthLog creates a new authentication log.
	CreateAuthLog(log *models.AuthLog) error

	// GetAuthLogs returns all authentication logs for the user.
	GetAuthLogs(userID int) ([]*models.AuthLog, error)

	// GetAuthLog returns the authentication log with the given ID.
	GetAuthLog(id int, userID int) (*models.AuthLog, error)

	// GetUserByEmail returns the user with the given email.
	GetUserByEmail(email string) (*models.User, error)

	// GetUserByUsername returns the user with the given username.
	GetUserByUsername(username string) (*models.User, error)

	// CreateUsedPassword creates a new used password.
	CreateUsedPassword(userID int, password string) error

	// GetUsedPasswords returns all used passwords for the user.
	GetUsedPasswords(userID int) ([]*models.UsedPassword, error)
}

// userService is the implementation of the UserService interface.
type userRepository struct {
	db *sql.DB
}

// NewUserService creates a new user service.
func NewUserRepository(db Service) UserRepository {
	return &userRepository{
		db: db.DB(),
	}
}

func (s *userRepository) CreateUser(user *models.User) (int, error) {
	res := s.db.QueryRow(`INSERT INTO auth_users (first_name, last_name, username, email, password, is_superadmin, is_admin, is_active) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`, user.FirstName, user.LastName, user.Username, user.Email, user.Password, user.IsSuperadmin, user.IsAdmin, user.IsActive)
	var id int
	err := res.Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, err
}

func (s *userRepository) GetUser(id int) (*models.User, error) {
	var user models.User
	query := `SELECT * FROM auth_users WHERE id = $1`

	err := s.db.QueryRow(query, id).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Username, &user.Email, &user.Password, &user.IsSuperadmin, &user.IsAdmin, &user.IsActive, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	return &user, err
}

func (s *userRepository) GetUsers(optional *types.UserAccessFilter) ([]*models.User, error) {
	// Build the SQL query
	query, err := utils.BuildUserAccessSQL(optional)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		var user models.User
		err = rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Username, &user.Email, &user.Password, &user.IsSuperadmin, &user.IsAdmin, &user.IsActive, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (s *userRepository) UpdateUser(user *models.User) error {
	_, err := s.db.Exec("UPDATE auth_users SET first_name = COALESCE(NULLIF($1, ''), first_name), last_name = COALESCE(NULLIF($2, ''), last_name), username = COALESCE(NULLIF($3, ''), username), email = COALESCE(NULLIF($4, ''), email), password = COALESCE(NULLIF($5, ''), password), is_superadmin = COALESCE(NULLIF($6, is_superadmin), is_superadmin), is_admin = COALESCE(NULLIF($7, is_admin), is_admin), is_active = COALESCE(NULLIF($8, is_active), is_active) WHERE id = $9", user.FirstName, user.LastName, user.Username, user.Email, user.Password, user.IsSuperadmin, user.IsAdmin, user.IsActive, user.ID)
	return err
}

func (s *userRepository) DeleteUser(id int) error {
	_, err := s.db.Exec("UPDATE auth_users SET deleted_at = NOW() WHERE id = $1", id)
	return err
}

func (s *userRepository) HardDeleteUser(id int) error {
	_, err := s.db.Exec("DELETE FROM auth_users WHERE id = $1", id)
	return err
}

func (s *userRepository) CreateAuthLog(log *models.AuthLog) error {
	_, err := s.db.Exec("INSERT INTO auth_logs (user_id, ip_address, user_agent) VALUES ($1, $2, $3)", log.UserID, log.IPAddress.String(), log.UserAgent)
	return err
}

func (s *userRepository) GetAuthLogs(userID int) ([]*models.AuthLog, error) {
	rows, err := s.db.Query("SELECT * FROM auth_logs WHERE user_id = $1 ORDER BY created_at DESC", userID)
	if err != nil {
		return nil, err
	}

	var logs []*models.AuthLog
	for rows.Next() {
		var log models.AuthLog
		var ip string
		err = rows.Scan(&log.ID, &log.UserID, &ip, &log.UserAgent, &log.CreatedAt)
		if err != nil {
			return nil, err
		}
		log.IPAddress = net.ParseIP(ip)
		logs = append(logs, &log)
	}

	return logs, nil
}

func (s *userRepository) GetAuthLog(id int, userID int) (*models.AuthLog, error) {
	var log models.AuthLog
	var ip string
	err := s.db.QueryRow("SELECT * FROM auth_logs WHERE id = $1 AND user_id = $2", id, userID).Scan(&log.ID, &log.UserID, &ip, &log.UserAgent, &log.CreatedAt)
	log.IPAddress = net.ParseIP(ip)
	return &log, err
}

func (s *userRepository) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	err := s.db.QueryRow("SELECT * FROM auth_users WHERE email = $1", email).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Username, &user.Email, &user.Password, &user.IsSuperadmin, &user.IsAdmin, &user.IsActive, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	return &user, err
}

func (s *userRepository) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := s.db.QueryRow("SELECT * FROM auth_users WHERE username = $1", username).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Username, &user.Email, &user.Password, &user.IsSuperadmin, &user.IsAdmin, &user.IsActive, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt)
	return &user, err
}

func (s *userRepository) CreateUsedPassword(userID int, password string) error {
	_, err := s.db.Exec("INSERT INTO auth_passwords (user_id, password) VALUES ($1, $2)", userID, password)
	return err
}

func (s *userRepository) GetUsedPasswords(userID int) ([]*models.UsedPassword, error) {
	rows, err := s.db.Query("SELECT * FROM auth_passwords WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5", userID)
	if err != nil {
		return nil, err
	}
	var usedPasswords []*models.UsedPassword

	for rows.Next() {
		var usedPassword models.UsedPassword
		err = rows.Scan(&usedPassword.ID, &usedPassword.UserID, &usedPassword.Password, &usedPassword.CreatedAt)
		if err != nil {
			return nil, err
		}
		usedPasswords = append(usedPasswords, &usedPassword)
	}

	return usedPasswords, nil
}

func (s *userRepository) DeleteUsedPassword(id int) error {
	_, err := s.db.Exec("DELETE FROM auth_passwords WHERE id = $1", id)
	return err
}
