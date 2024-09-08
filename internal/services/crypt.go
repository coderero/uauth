package services

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	empty = "" // empty string
)

// CryptService is the interface for the crypt service.
type CryptService interface {

	// Hash hashes the input string
	Hash(input string) (string, error)

	// Compare compares the input string with the hash
	Compare(input, hash string) error

	// ReHash regenerates the hash from the same salt that was supplied in the hash
	ReHash(hash, password string) (string, error)

	// encode encodes the derived key and salt into a string
	encode(dk, salt []byte) string

	// salt generates a random salt
	salt() ([]byte, error)

	// decode decodes the hash into the derived key and salt
	decode(hash string) ([]byte, []byte, error)
}

type cryptService struct {
	cost        int // The cpu cost factor for scrypt commonly denoted as N
	rounds      int // The memory cost factor for scrypt commonly denoted as r
	parallelism int // The parallelism factor for scrypt commonly denoted as p
	keyLen      int // The length of the key to be generated
	saltLen     int // The length of the salt to be generated
}

// NewCryptService creates a new crypt service.
func NewCryptService(cost, rounds, parallelism, keyLen, saltLen int) CryptService {
	return &cryptService{
		cost:        cost,
		rounds:      rounds,
		parallelism: parallelism,
		keyLen:      keyLen,
		saltLen:     saltLen,
	}
}

func (s *cryptService) Hash(input string) (string, error) {
	salt, err := s.salt()
	if err != nil {
		return empty, err
	}

	dk, err := scrypt.Key([]byte(input), salt, 1<<s.cost, s.rounds, s.parallelism, s.keyLen)
	if err != nil {
		return empty, err
	}

	return s.encode(dk, salt), nil
}

func (s *cryptService) Compare(input, hash string) error {
	dk, salt, err := s.decode(hash)
	if err != nil {
		return err
	}

	dk2, err := scrypt.Key([]byte(input), salt, 1<<s.cost, s.rounds, s.parallelism, s.keyLen)
	if err != nil {
		return err
	}

	if !hmac.Equal(dk, dk2) {
		return ErrInvalidPassword
	}

	return nil
}

func (s *cryptService) ReHash(hash, password string) (string, error) {
	_, salt, err := s.decode(hash)
	if err != nil {
		return empty, err
	}

	newDk, err := scrypt.Key([]byte(password), salt, 1<<s.cost, s.rounds, s.parallelism, s.keyLen)
	if err != nil {
		return empty, err
	}

	return s.encode(newDk, salt), nil
}

func (s *cryptService) salt() ([]byte, error) {
	var b = make([]byte, s.saltLen)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *cryptService) encode(dk, salt []byte) string {
	hash := base64.StdEncoding.EncodeToString(dk)
	saltStr := base64.StdEncoding.EncodeToString(salt)

	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", s.cost, s.rounds, s.parallelism, saltStr, hash)
}

func (s *cryptService) decode(hash string) ([]byte, []byte, error) {
	params := strings.Split(hash, "$")
	if len(params) != 6 {
		return nil, nil, fmt.Errorf("invalid hash")
	}

	salt, err := base64.StdEncoding.DecodeString(params[4])
	if err != nil {
		return nil, nil, err
	}

	dk, err := base64.StdEncoding.DecodeString(params[5])
	if err != nil {
		return nil, nil, err
	}

	return dk, salt, nil
}
