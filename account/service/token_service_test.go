package service

import (
	"context"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewPairFromUser(t *testing.T) {
	var idExp int64 = 15 * 60
	var refreshExp int64 = 3 * 24 * 2600
	priv, _ := ioutil.ReadFile("../rsa_private_test.pem")
	privKey, _ := jwt.ParseRSAPrivateKeyFromPEM(priv)
	pub, _ := ioutil.ReadFile("../rsa_public_test.pem")
	pubKey, _ := jwt.ParseRSAPublicKeyFromPEM(pub)
	secret := "randomtestsecret"

	mockTokenRepository := new(mocks.MockTokenRepository)

	tokenService := NewTokenService(&TSConfig{
		TokenRepository: mockTokenRepository,
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

	uidErrorCase, _ := uuid.NewRandom()
	uErrorCase := &model.User{
		UID: uidErrorCase,
		Email: "failure@failure.com",
		Password: "samplepassword",
	}
	prevID := "a_previous_tokenID"

	setSuccessArguments := mock.Arguments {
		mock.AnythingOfType("*context.emptyCtx"),
		u.UID.String(),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("time.Duration"),
	}

	setErrorArguments := mock.Arguments{
		mock.AnythingOfType("*context.emptyCtx"),
		uidErrorCase.String(),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("time.Duration"),
	}

	deleteWithPrevIDArguments := mock.Arguments{
		mock.AnythingOfType("*context.emptyCtx"),
		u.UID.String(),
		prevID,
	}

	mockTokenRepository.On("SetRefreshToken", setSuccessArguments...).Return(nil)
	mockTokenRepository.On("SetRefreshToken", setErrorArguments...).Return(fmt.Errorf("Error setting refresh token"))
	mockTokenRepository.On("DeleteRefreshToken", deleteWithPrevIDArguments...).Return(nil)

	t.Run("Returns a token pair with proper values", func(t *testing.T) {
		ctx := context.Background()
		tokenPair, err := tokenService.NewPairFromUser(ctx, u, prevID)
		assert.NoError(t, err)

		mockTokenRepository.AssertCalled(t, "SetRefreshToken", setSuccessArguments...)
		mockTokenRepository.AssertCalled(t, "DeleteRefreshToken", deleteWithPrevIDArguments...)

		var s string
		assert.IsType(t, s, tokenPair.IDToken.SS)

		idTokenClaims := &idTokenCustomClaims{}

		_, err = jwt.ParseWithClaims(tokenPair.IDToken.SS, idTokenClaims, func(token *jwt.Token) (interface{}, error) {
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

		refreshTokenClaims := &refreshTokenCustomClaims{}
		_, err = jwt.ParseWithClaims(tokenPair.RefreshToken.SS, refreshTokenClaims,
		func(t *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})

		assert.IsType(t, s, tokenPair.RefreshToken.SS)

		assert.NoError(t, err)
		assert.Equal(t, u.UID, refreshTokenClaims.UID)

		expiresAt = time.Unix(refreshTokenClaims.StandardClaims.ExpiresAt, 0)
		expectedExpiresAt = time.Now().Add(time.Duration(refreshExp) * time.Second)
		assert.WithinDuration(t, expectedExpiresAt, expiresAt, 5*time.Second)
	})

	t.Run("Error setting refresh token", func(t *testing.T) {
		ctx := context.Background()
		_, err := tokenService.NewPairFromUser(ctx, uErrorCase, "")
		assert.Error(t, err)

		mockTokenRepository.AssertCalled(t, "SetRefreshToken", setErrorArguments...)

		mockTokenRepository.AssertNotCalled(t, "DeleteRefreshToken")
	})

	t.Run("Empty string provided for prevID", func(t *testing.T) {
		ctx := context.Background()
		_, err := tokenService.NewPairFromUser(ctx, u, "")
		assert.NoError(t, err)

		mockTokenRepository.AssertCalled(t, "SetRefreshToken", setSuccessArguments...)

		mockTokenRepository.AssertNotCalled(t, "DeleteRefreshToken")
	})
}