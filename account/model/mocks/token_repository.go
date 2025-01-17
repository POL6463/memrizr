package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
)

type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) SetRefreshToken(ctx context.Context, userID string, tokenID string, expiresIn time.Duration) error {
	ret := m.Called(ctx, userID, tokenID, expiresIn)

	var r0 error

	if ret.Get(0) != nil {
		r0 = ret.Get(0).(error)
	}

	return r0
}

func (m *MockTokenRepository) DeleteRefreshToken(ctx context.Context, userID string, prevTokenID string) error {
	ret := m.Called(ctx, userID, prevTokenID)

	var r0 error

	if ret.Get(0) != nil {
		r0 = ret.Get(0).(error)
	}

	return r0
}

//DeleateUserRefreshTokens mocks concrete DeleateUserRefreshTokens
func (m *MockTokenRepository) DeleateUserRefreshTokens(ctx context.Context, userID string) error {
	ret := m.Called(ctx, userID)

	var r0 error

	if ret.Get(0) != nil {
		r0 = ret.Get(0).(error)
	}

	return r0
}