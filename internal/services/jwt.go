package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/coderero/paas-project/internal/cache"
	"github.com/coderero/paas-project/internal/types"
	"github.com/golang-jwt/jwt/v5"
)

const (
	algorithm string = "ES256"
)

type JwtService interface {
	// GenerateToken generates a new token with the given string and type.
	GenerateToken(*types.TokenConfig) (string, error)

	// ValidateToken validates the given token with the given type.
	IsValidToken(string, types.TokenType) (bool, error)

	// RevokeToken revokes the given token with the given type.
	RevokeToken(string, string) error

	// GetClaims returns the claims of the given token.
	GetClaims(string) (*jwt.MapClaims, error)
}

// jwtService is the implementation of the JwtService interface.
type jwtService struct {
	jwtCache   cache.JwtCache
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewJwtService creates a new jwt service.
func NewJwtService(jwtCache cache.JwtCache) JwtService {
	privateKey := getPrivateKey()
	publicKey := getPublicKey()

	if privateKey == nil || publicKey == nil {
		privateKey, publicKey = generateKeys()
	}
	return &jwtService{
		jwtCache:   jwtCache,
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (s *jwtService) GenerateToken(config *types.TokenConfig) (string, error) {
	var (
		expiry int64
	)
	if config.Typ == types.AccessToken {
		expiry = time.Now().Add(time.Hour * 24).Unix()
	} else {
		expiry = time.Now().Add(time.Hour * 24 * 7).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.MapClaims{
		"alg":  algorithm,
		"sub":  config.Sub,
		"typ":  config.Typ.String(),
		"role": "user",
		"exp":  expiry,
		"iat":  time.Now().Unix(),
	})

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return empty, err
	}

	return tokenString, err

}

func (s *jwtService) IsValidToken(token string, typ types.TokenType) (bool, error) {
	// Parse the token
	if token == "" {
		return false, nil
	}

	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})
	if err != nil {
		return false, err
	}

	// Check if the token is valid
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return false, nil
	}

	valid := s.jwtCache.IsRevoked(context.Background(), claims["sub"].(string), token)
	if !valid || !t.Valid {
		return false, nil
	}

	return true, nil
}

func (s *jwtService) RevokeToken(sub, token string) error {
	return s.jwtCache.Revoke(context.Background(), sub, token)
}

func (s *jwtService) GetClaims(token string) (*jwt.MapClaims, error) {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}

	return &claims, nil
}

func getPrivateKey() *ecdsa.PrivateKey {
	key, err := os.ReadFile("./certs/private.pem")
	if err != nil {
		return nil
	}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil
	}

	return privateKey
}

func getPublicKey() *ecdsa.PublicKey {
	key, err := os.ReadFile("./certs/public.pem")
	if err != nil {
		return nil
	}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil
	}

	return publicKey
}

func generateKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil
	}

	publicKey := &privateKey.PublicKey

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil
	}

	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	privateKeyFile, err := os.Create("./certs/private.pem")
	if err != nil {
		return nil, nil
	}

	publicKeyFile, err := os.Create("./certs/public.pem")
	if err != nil {
		return nil, nil
	}

	pem.Encode(privateKeyFile, privateKeyBlock)
	pem.Encode(publicKeyFile, publicKeyBlock)

	return privateKey, publicKey
}
