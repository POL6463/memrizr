package service

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/apperrors"
)

type UserService struct {
	UserRepository model.UserRepository
}

type USConfig struct {
	UserRepository model.UserRepository
}

func NewUserService(c *USConfig) model.UserService {
	return &UserService {
		UserRepository: c.UserRepository,
	}
}
func (s *UserService) Get(ctx context.Context, uid uuid.UUID) (*model.User ,error) {
	u, err := s.UserRepository.FindByID(ctx, uid)

	return u, err
}

func (s *UserService) Signup(ctx context.Context, u *model.User) error {
	pw, err := hashPassword(u.Password)

	if err != nil {
		log.Printf("Unable to signup user for email: %v\n", u.Email)
		return apperrors.NewInternal()
	}

	u.Password = pw

	if err := s.UserRepository.Create(ctx, u); err != nil {
		return err
	}

	// If we get around to adding events, we'd Publish it here -- maybe pubsub?
	// err := s.EventBroker.PublishUserUpdated(u, true)

	return nil
}