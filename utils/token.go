package utils

import (
	"go-auth-paseto/models"
	"log"
	"os"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"
)

var (
	symmetricKey paseto.V4SymmetricKey
	err          error
)

func GenerateToken(user *models.User) (string, error) {
	token := paseto.NewToken()
	token.Set("id", user.ID)
	token.SetString("username", user.Username)
	token.Set("role", user.Role)
	token.SetIssuedAt(time.Now())
	token.SetNotBefore(time.Now())
	token.SetExpiration(time.Now().Add(2 * time.Hour)) // Token expiration time (2 hours)
	token.SetJti(uuid.New().String())

	symmetricKey, err = paseto.V4SymmetricKeyFromBytes([]byte(os.Getenv("PASETO_RANDOM_KEY")))
	if err != nil {
		log.Printf("Error generating symmetric key: %v", err)
		return "", err
	}

	encrypted := token.V4Encrypt(symmetricKey, nil)

	return encrypted, nil
}

func GetTokenClaims(tokenString string) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	symmetricKey, err = paseto.V4SymmetricKeyFromBytes([]byte(os.Getenv("PASETO_RANDOM_KEY")))
	if err != nil {
		log.Printf("Error generating symmetric key: %v", err)
		return nil, err
	}

	parsedToken, err := parser.ParseV4Local(symmetricKey, tokenString, nil)
	if err != nil {
		log.Printf("Error parsing token: %v", err)
		return nil, err
	}

	return parsedToken, nil
}
