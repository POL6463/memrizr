package service

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/stretchr/testify/assert"
)

func TestNewPairFromUser(t *testing.T) {
	var idExp int64 = 15 * 60
	var refreshExp int64 = 3 * 24 * 2600
	priv, _ := ioutil.ReadFile("../rsa_private_test.pem")
	privKey, _ := jwt.ParseRSAPrivateKeyFromPEM(priv)
	pub, _ := ioutil.ReadFile("../rsa_public_test.pem")
	pubKey, _ := jwt.ParseRSAPublicKeyFromPEM(pub)
	secret := "randomtestsecret"

	tokenService := NewTokenService(&TSConfig{
		PrivKey: privKey,
		PubKey: pubKey,
		RefreshSecret: secret,
		IDExpiratonSecs: idExp,
		RefreshExpirationSecs: refreshExp,
	})

	uid, _ := uuid.NewRandom()
	u := &model.User{
		UID: uid,
		Email: "bob@bob.com",
		Password: "passwordpassword",
	}

	t.Run("returns a token pair with proper values", func(t *testing.T) {
		ctx := context.TODO()
		tokenPair, err := tokenService.NewPairFromUser(ctx, u, "")
		assert.NoError(t, err)

		var s string
		assert.IsType(t, s, tokenPair.IDToken)

		idTokenClaims := &IDTokenCustomClaims{}

		_, err = jwt.ParseWithClaims(tokenPair.IDToken, idTokenClaims, func(token *jwt.Token) (interface{}, error) {
			return pubKey, nil
		})

		assert.NoError(t, err)

		expectedClaims := []interface{}{
			u.UID,
			u.Email,
			u.Name,
			u.ImageURL,
			u.Website,
		}
		actualIDClaims := []interface{}{
			idTokenClaims.User.UID,
			idTokenClaims.User.Email,
			idTokenClaims.User.Name,
			idTokenClaims.User.ImageURL,
			idTokenClaims.User.Website,
		}

		assert.ElementsMatch(t, expectedClaims, actualIDClaims)
		assert.Empty(t, idTokenClaims.User.Password)

		expiresAt := time.Unix(idTokenClaims.StandardClaims.ExpiresAt, 0)
		expectedExpiresAt := time.Now().Add(time.Duration(idExp) * time.Second)
		assert.WithinDuration(t, expectedExpiresAt, expiresAt, 5*time.Second)

		refreshTokenClaims := &RefreshTokenCustomClaims{}
		_, err = jwt.ParseWithClaims(tokenPair.RefreshToken, refreshTokenClaims,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})

		assert.IsType(t, s, tokenPair.RefreshToken)

		assert.NoError(t, err)
		assert.Equal(t, u.UID, refreshTokenClaims.UID)

		expiresAt = time.Unix(refreshTokenClaims.StandardClaims.ExpiresAt, 0)
		expectedExpiresAt = time.Now().Add(time.Duration(refreshExp) * time.Second)
		assert.WithinDuration(t, expectedExpiresAt, expiresAt, 5*time.Second)
	})
}