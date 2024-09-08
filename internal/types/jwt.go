package types

// TokenType is an enum for token types
type TokenType int

const (
	AccessToken  TokenType = iota // AccessToken
	RefreshToken                  // RefreshToken
)

// String returns the string representation of the token type
func (t TokenType) String() string {
	return [...]string{"access_token", "refresh_token"}[t]
}

// Tokens is a struct that contains the access and refresh tokens
type Tokens struct {
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// TokenConfig is a struct that contains the token configuration
type TokenConfig struct {
	Sub  string
	Typ  TokenType
	Role string
}
