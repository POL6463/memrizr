package service

import (
	"context"
	"crypto/rsa"
	"log"

	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/apperrors"
)

type TokenService struct {
	PrivKey 		*rsa.PrivateKey
	PubKey 			*rsa.PublicKey
	RefreshSecret 	string
}

type TSConfig struct {
	PrivKey 		*rsa.PrivateKey
	PubKey 			*rsa.PublicKey
	RefreshSecret 	string
}

func NewTokenService(c *TSConfig) model.TokenService {
	return &TokenService{
		PrivKey: 		c.PrivKey,
		PubKey: 		c.PubKey,
		RefreshSecret:	c.RefreshSecret,
	}
}

func (s *TokenService) NewPairFromUser(ctx context.Context, u *model.User, prevTokenID string) (*model.TokenPair, error){
	
	idToken, err := generateIDToken(u, s.PrivKey)

	if err != nil {
		log.Printf("Error generating idToken for uid: %v. Error: %v\n", u.UID, err.Error())
		return nil, apperrors.NewInternal()
	}

	refreshToken, err := generateRefreshToken(u.UID, s.RefreshSecret)

	if err != nil {
		log.Printf("Error generating refreshToken for uid: %v. Error: %v\n", u.UID, err.Error())
		return nil, apperrors.NewInternal()
	}

	return &model.TokenPair{
		IDToken: idToken,
		RefreshToken: refreshToken.SS,
	}, nil
}