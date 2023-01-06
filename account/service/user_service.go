package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/jacobsngoodwin/memrizr/account/model"
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
	if err := s.UserRepository.Create(ctx, u); err != nil {
		return err
	}

	return nil
}