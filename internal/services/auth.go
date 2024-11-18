package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/coderero/paas-project/api/models"
	"github.com/coderero/paas-project/internal/cache"
	"github.com/coderero/paas-project/internal/database"
	"github.com/coderero/paas-project/internal/types"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/sync/errgroup"
)

var (
	// TokenKey is the key used to encrypt the tokens for reset password and email verification.
	key = os.Getenv("TOKEN_KEY")

	// ErrUserNotFound is the error returned when a user is not found.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserNotActive is the error returned when a user is not active.
	ErrUserNotActive = errors.New("user not active")

	// ErrInvalidPassword is the error returned when a password is invalid.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrInvalidToken is the error returned when a token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrInvalidRefreshToken is the error returned when a refresh token is invalid.
	ErrInvalidRefreshToken = errors.New("invalid refresh token")

	// ErrFailedToGenerateToken is the error returned when a token cannot be generated.
	ErrFailedToGenerateToken = errors.New("failed to generate token")

	// ErrUserAlreadyExists is the error returned when a user already exists.
	ErrUserAlreadyExists = errors.New("user already exists with the given email or username")

	// ErrPasswordAlreadyUsed is the error returned when a password is already used.
	ErrPasswordAlreadyUsed = errors.New("password already used")

	// ErrFailedToSendEmail is the error returned when an email cannot be sent.
	ErrFailedToSendEmail = errors.New("failed to send email")

	// ErrTokenGeneration is the error returned when a token cannot be generated.
	ErrTokenGeneration = errors.New("failed to generate token")
)

// AuthServicer is the interface that provides authentication methods.
type AuthServicer interface {
	// Register registers a user with the given email and password.
	Register(ctx context.Context, user *models.User) (*types.Tokens, int, error)

	// RegenEmailVerification regenerates the email verification token for the user with the given email.
	RegenEmailVerification(ctx context.Context, email string) error

	// VerifyEmail verifies the email for the user with the given token.
	VerifyEmail(ctx context.Context, token string) error

	// Login logs in a user with the given email and password.
	Login(ctx context.Context, email, password string) (*types.Tokens, int, error)

	// ResetPassword resets the password for the user with the given email.
	ResetPassword(ctx context.Context, email string) error

	// VerifyAndResetPassword verifies and resets the password for the user with the given email.
	VerifyAndResetPassword(ctx context.Context, payload string, newPassword string) error

	// ChangePassword changes the password for the user with the given email.
	ChangePassword(ctx context.Context, email, oldPassword, newPassword string) error

	// CreateUsedPassword creates a new used password.
	CreateUsedPassword(ctx context.Context, userID int, password string) error

	// CreateAuthLog creates a new authentication log.
	CreateAuthLog(ctx context.Context, userId int, ip, userAgent string) error

	// Logout logs out a user with the given refresh token.
	Logout(ctx context.Context, refreshToken, accessToken string) error
}

type payload struct {
	ID     uuid.UUID `json:"id"`
	Email  string    `json:"email"`
	Expiry int64     `json:"expiry"`
}

type authService struct {
	cryptService   CryptService
	userRepository database.UserRepository
	userCache      cache.UserCache
	jwtService     JwtService
	smtpService    SmtpService
}

// NewAuthService creates a new authentication service.
func NewAuthService(crypt CryptService, userRepository database.UserRepository, userCache cache.UserCache, jwt JwtService) AuthServicer {
	return &authService{
		cryptService:   crypt,
		userRepository: userRepository,
		userCache:      userCache,
		jwtService:     jwt,
		smtpService:    NewSmtpService(),
	}
}

func (s *authService) Login(ctx context.Context, email, password string) (*types.Tokens, int, error) {
	// Find the user in the database
	u, err := s.userRepository.GetUserByEmail(email)
	if err != nil {
		return nil, 0, ErrUserNotFound
	}

	// Check if the user data is not nil
	if u == nil {
		return nil, 0, ErrUserNotFound
	}

	if !u.IsActive {
		return nil, 0, ErrUserNotActive
	}

	// Compare the password
	if err := s.cryptService.Compare(password, u.Password); err != nil {
		return nil, 0, ErrInvalidPassword
	}

	tokens, err := s.generateTokens(ctx, s, u)
	if err != nil {
		return nil, 0, ErrFailedToGenerateToken
	}

	return tokens, u.ID, nil
}

func (s *authService) Register(ctx context.Context, user *models.User) (*types.Tokens, int, error) {
	// Get the user by email and username
	g, _ := errgroup.WithContext(ctx)
	var emailExists, usernameExists bool = true, true
	g.Go(func() error {
		var err error
		_, err = s.userRepository.GetUserByEmail(user.Email)
		if errors.Is(err, sql.ErrNoRows) {
			emailExists = false
			return nil
		}
		return err
	})
	g.Go(func() error {
		var err error
		_, err = s.userRepository.GetUserByUsername(user.Username)
		if errors.Is(err, sql.ErrNoRows) {
			usernameExists = false
			return nil
		}
		return err
	})

	if err := g.Wait(); err != nil {
		return nil, 0, err
	}

	if emailExists || usernameExists {
		return nil, 0, ErrUserAlreadyExists
	}

	hash, err := s.cryptService.Hash(user.Password)
	if err != nil {
		return nil, 0, err
	}

	user.Password = hash

	var errgroup errgroup.Group
	var id int
	errgroup.Go(func() error {
		var err error
		id, err = s.userRepository.CreateUser(user)
		return err
	})

	errgroup.Go(func() error {
		if !user.IsActive {
			if err := s.userCache.SetInactiveUser(user.Email); err != nil {
				return err
			}
		}

		token, err := s.encryptRPP(&payload{
			ID:     uuid.New(),
			Email:  user.Email,
			Expiry: time.Now().Add(time.Hour).Unix(),
		})

		if err != nil {
			return ErrTokenGeneration
		}

		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := s.smtpService.Send(ctx, user.Email, "Verify Email", fmt.Sprintf("Click the link to verify your email: http://localhost:3000/verify-email?token=%s", token)); err != nil {
			return ErrFailedToSendEmail
		}
		return nil
	})

	if err := errgroup.Wait(); err != nil {
		return nil, 0, err
	}

	tokens, err := s.generateTokens(ctx, s, user)
	if err != nil {
		return nil, 0, ErrFailedToGenerateToken
	}

	return tokens, id, nil
}

func (s *authService) RegenEmailVerification(ctx context.Context, email string) error {
	// Find the user in the database
	u, err := s.userRepository.GetUserByEmail(email)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	// Generate Verification Token
	t, err := s.encryptRPP(&payload{
		ID:     uuid.New(),
		Email:  u.Email,
		Expiry: time.Now().Add(time.Hour).Unix(),
	})

	if err != nil {
		return ErrFailedToGenerateToken
	}

	// Context timeout for the email sending
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Send the email
	if err := s.smtpService.Send(ctx, u.Email, "Verify Email", fmt.Sprintf("Click the link to verify your email: http://localhost:3000/verify-email?token=%s", t)); err != nil {
		return ErrFailedToGenerateToken
	}

	return nil
}

func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	// Decrypt the token
	p, err := s.decryptRPP(token)
	if err != nil {
		return ErrInvalidToken
	}

	// Check if the token is expired
	if time.Now().Unix() > p.Expiry {
		return ErrInvalidToken
	}

	// Find the user in the database
	u, err := s.userRepository.GetUserByEmail(p.Email)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	// Activate the user
	u.IsActive = true
	if err := s.userRepository.UpdateUser(u); err != nil {
		return err
	}

	// Remove the inactive user from the cache
	if err := s.userCache.RemoveInactiveUser(u.Email); err != nil {
		return err
	}

	return nil
}

func (s *authService) Logout(ctx context.Context, refreshToken, accessToken string) error {
	g, _ := errgroup.WithContext(ctx)

	var accessValid, refreshValid bool

	g.Go(func() error {
		var err error
		accessValid, err = s.jwtService.IsValidToken(accessToken, types.AccessToken)
		return err
	})

	g.Go(func() error {
		var err error
		refreshValid, err = s.jwtService.IsValidToken(refreshToken, types.RefreshToken)
		return err
	})

	if err := g.Wait(); err != nil {
		return err
	}

	if !accessValid || !refreshValid {
		return ErrInvalidToken
	}

	claims, err := s.jwtService.GetClaims(refreshToken)
	if err != nil {
		return err
	}

	g.Go(func() error {
		return s.jwtService.RevokeToken((*claims)["sub"].(string), accessToken)
	})

	g.Go(func() error {
		return s.jwtService.RevokeToken((*claims)["sub"].(string), refreshToken)
	})

	return g.Wait()
}

func (s *authService) ResetPassword(ctx context.Context, email string) error {
	// Find the user in the database
	u, err := s.userRepository.GetUserByEmail(email)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	// Generate a reset password payload
	payload := payload{
		ID:     uuid.New(),
		Email:  email,
		Expiry: time.Now().Add(time.Hour).Unix(),
	}

	// Encrypt the payload
	encrypted, err := s.encryptRPP(&payload)
	if err != nil {
		return err
	}
	log.Printf("Reset password payload: %+v", payload)

	// Context timeout for the email sending
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Send the email
	if err := s.smtpService.Send(ctx, email, "Reset Password", fmt.Sprintf("Click the link to reset your password: http://localhost:3000/reset-password?payload=%s", encrypted)); err != nil {
		return ErrFailedToSendEmail
	}

	return nil
}

func (s *authService) VerifyAndResetPassword(ctx context.Context, payload string, newPassword string) error {
	// Decrypt the payload
	p, err := s.decryptRPP(payload)
	if err != nil {
		return ErrInvalidToken
	}

	// Check if the payload is expired
	if time.Now().Unix() > p.Expiry {
		return ErrInvalidToken
	}

	// Find the user in the database
	u, err := s.userRepository.GetUserByEmail(p.Email)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	return s.updatePass(ctx, newPassword, u)
}

func (s *authService) ChangePassword(ctx context.Context, email, oldPassword, newPassword string) error {
	// Find the user in the database
	u, err := s.userRepository.GetUserByEmail(email)
	if err != nil || u == nil {
		return ErrUserNotFound
	}

	return s.updatePass(ctx, newPassword, u)
}

func (s *authService) CreateUsedPassword(ctx context.Context, userID int, password string) error {
	return s.userRepository.CreateUsedPassword(userID, password)
}

func (s *authService) CreateAuthLog(ctx context.Context, userId int, ip, userAgent string) error {
	return s.userRepository.CreateAuthLog(&models.AuthLog{
		UserID:    userId,
		IPAddress: net.ParseIP(ip),
		UserAgent: userAgent,
	})
}

func (s *authService) updatePass(ctx context.Context, newPassword string, u *models.User) error {
	if u == nil {
		return ErrUserNotFound
	}
	if err := s.cryptService.Compare(newPassword, u.Password); err == nil {
		return ErrPasswordAlreadyUsed
	}

	pass, err := s.userRepository.GetUsedPasswords(u.ID)
	if err != nil {
		return err
	}

	g, _ := errgroup.WithContext(ctx)
	for _, p := range pass {
		g.Go(func() error {
			err := s.cryptService.Compare(newPassword, p.Password)
			return err
		})
	}

	err = g.Wait()
	if err != nil && !errors.Is(err, ErrInvalidPassword) {
		return err
	}

	if err == nil {
		return ErrPasswordAlreadyUsed
	}

	hash, err := s.cryptService.ReHash(u.Password, newPassword)
	if err != nil {
		return err
	}

	u.Password = hash

	if err := s.userRepository.CreateUsedPassword(u.ID, newPassword); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return ErrPasswordAlreadyUsed
		}
		return err
	}

	return s.userRepository.UpdateUser(u)
}

func (a *authService) generateTokens(ctx context.Context, s *authService, user *models.User) (*types.Tokens, error) {
	var accessToken, refreshToken string
	g, _ := errgroup.WithContext(ctx)

	g.Go(func() error {
		var err error
		accessToken, err = s.jwtService.GenerateToken(&types.TokenConfig{
			Sub:  user.Email,
			Typ:  types.AccessToken,
			Role: user.GetRole(),
		})
		return err
	})

	g.Go(func() error {
		var err error
		refreshToken, err = s.jwtService.GenerateToken(&types.TokenConfig{
			Sub:  user.Email,
			Typ:  types.RefreshToken,
			Role: user.GetRole(),
		})
		return err
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return &types.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// encryptRPP encrypts the reset password payload.
func (s *authService) encryptRPP(payload *payload) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return empty, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return empty, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return empty, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], b)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// decryptRPP decrypts the reset password payload.
func (s *authService) decryptRPP(encrypted string) (*payload, error) {
	// Decode the base64-encoded encrypted payload
	ciphertext, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// Ensure the ciphertext length is greater than the block size
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the IV from the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	// Unmarshal the decrypted JSON into a resetPasswordPayload struct
	var payload payload
	err = json.Unmarshal(ciphertext, &payload)
	if err != nil {
		return nil, err
	}

	return &payload, nil
}
