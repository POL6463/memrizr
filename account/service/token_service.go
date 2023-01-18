package service

import (
	"context"
	"crypto/rsa"
	"log"

	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/apperrors"
)

type tokenService struct {
	PrivKey 				*rsa.PrivateKey
	PubKey 					*rsa.PublicKey
	RefreshSecret 			string
	IDExpiratonSecs 		int64
	RefreshExpirationSecs 	int64
}

type TSConfig struct {
	PrivKey 				*rsa.PrivateKey
	PubKey 					*rsa.PublicKey
	RefreshSecret 			string
	IDExpiratonSecs 		int64
	RefreshExpirationSecs 	int64
}

func NewTokenService(c *TSConfig) model.TokenService {
	return &tokenService{
		PrivKey: 		c.PrivKey,
		PubKey: 		c.PubKey,
		RefreshSecret:	c.RefreshSecret,
		IDExpiratonSecs: c.IDExpiratonSecs,
		RefreshExpirationSecs: c.RefreshExpirationSecs,
	}
}

func (s *tokenService) NewPairFromUser(ctx context.Context, u *model.User, prevTokenID string) (*model.TokenPair, error){
	
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

	return &model.TokenPair{
		IDToken: idToken,
		RefreshToken: refreshToken.SS,
	}, nil
}