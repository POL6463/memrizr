package service

import (
	"context"
	"crypto/rsa"
	"log"

	"github.com/google/uuid"
	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/apperrors"
)

type tokenService struct {
	TokenRepository			model.TokenRepository
	PrivKey 				*rsa.PrivateKey
	PubKey 					*rsa.PublicKey
	RefreshSecret 			string
	IDExpiratonSecs 		int64
	RefreshExpirationSecs 	int64
}

type TSConfig struct {
	TokenRepository			model.TokenRepository
	PrivKey 				*rsa.PrivateKey
	PubKey 					*rsa.PublicKey
	RefreshSecret 			string
	IDExpiratonSecs 		int64
	RefreshExpirationSecs 	int64
}

func NewTokenService(c *TSConfig) model.TokenService {
	return &tokenService{
		TokenRepository: c.TokenRepository,
		PrivKey: 		c.PrivKey,
		PubKey: 		c.PubKey,
		RefreshSecret:	c.RefreshSecret,
		IDExpiratonSecs: c.IDExpiratonSecs,
		RefreshExpirationSecs: c.RefreshExpirationSecs,
	}
}

func (s *tokenService) NewPairFromUser(ctx context.Context, u *model.User, prevTokenID string) (*model.TokenPair, error){

	if prevTokenID != "" {
		if err := s.TokenRepository.DeleteRefreshToken(ctx, u.UID.String(), prevTokenID); err != nil {
			log.Printf("Could not delete previous refreshToken for uid: %v, tokenID: %v\n", u.UID.String(), prevTokenID)

			return nil, err
		}
	}

	idToken, err := generateIDToken(u, s.PrivKey, s.IDExpiratonSecs)

	if err != nil {
		log.Printf("Error generating idToken for uid: %v. Error: %v\n", u.UID, err.Error())
		return nil, apperrors.NewInternal()
	}

	refreshToken, err := generateRefreshToken(u.UID, s.RefreshSecret, s.RefreshExpirationSecs)

	if err != nil {
		log.Printf("Error generating refreshToken for uid: %v. Error: %v\n", u.UID, err.Error())
		return nil, apperrors.NewInternal()
	}

	if err := s.TokenRepository.SetRefreshToken(ctx, u.UID.String(), refreshToken.ID.String(), refreshToken.ExpiresIn); err != nil {
		log.Printf("Error storing tokenID for uid: %v. Error: %v\n", u.UID, err.Error())
		return nil, apperrors.NewInternal()
	}

	return &model.TokenPair{
		IDToken: model.IDToken{SS: idToken},
		RefreshToken: model.RefreshToken{SS: refreshToken.SS, ID: refreshToken.ID, UID: u.UID},
	}, nil
}

func (s *tokenService) ValidateIDToken(tokenString string) (*model.User, error) {
	claims, err := validateIDToken(tokenString, s.PubKey)

	if err != nil {
		log.Printf("Unable to validate or parse idToken - Error: %v\n", err)
		return nil, apperrors.NewAuthorization("Unable to verify user from idToken")
	}

	return claims.User, nil
}

func (s *tokenService) ValidateRefreshToken(tokenString string) (*model.RefreshToken, error) {

	claims, err := validateRefreshToken(tokenString, s.RefreshSecret)

	if err != nil {
		log.Printf("Unable to validate or parse refreshToken for token string: %s\n%v\n", tokenString, err)
		return nil, apperrors.NewAuthorization("Unable to verify user from rehresh token")
	}

	tokenUUID, err := uuid.Parse(claims.Id)

	if err != nil {
		log.Printf("Claims ID could not be parsed as UUID: %s\n%v\n", claims.Id, err)
		return nil, apperrors.NewAuthorization("Unable to verity user from refresh token")
	}
	return &model.RefreshToken{
		SS: tokenString,
		ID: tokenUUID,
		UID: claims.UID,
	}, nil
}
