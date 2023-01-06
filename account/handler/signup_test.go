package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/apperrors"
	"github.com/jacobsngoodwin/memrizr/account/model/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSignup(t *testing.T) {

	gin.SetMode(gin.TestMode)

	t.Run("Email and Password Required", func(t *testing.T) {

		mockUserService := new(mocks.MockUserService)
		mockUserService.On("Signup", mock.AnythingOfType("*gin.Context"), mock.AnythingOfType("*model.User")).Return(nil)

		rr := httptest.NewRecorder()

		router := gin.Default()

		NewHandler(&Config{
			R:				router,
			UserService:	mockUserService,
		})

		reqBody, err := json.Marshal(gin.H{
			"email": "",
		})
		assert.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(reqBody))
		assert.NoError(t, err)

		request.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(rr, request)

		assert.Equal(t, 400, rr.Code)
		mockUserService.AssertNotCalled(t, "Signup")

	})

	t.Run("Invalid email", func(t *testing.T) {

		mockUserService := new(mocks.MockUserService)
		mockUserService.On("Signup", mock.AnythingOfType("*gin.Context"), mock.AnythingOfType("*model.User")).Return(nil)

		rr := httptest.NewRecorder()

		router := gin.Default()

		NewHandler(&Config{
			R:				router,
			UserService:	mockUserService,
		})

		reqBody, err := json.Marshal(gin.H{
			"email": "bob@bob",
			"password": "supersecret1234",
		})
		assert.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(reqBody))
		assert.NoError(t, err)

		request.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(rr, request)

		assert.Equal(t, 400, rr.Code)
		mockUserService.AssertNotCalled(t, "Signup")

	})

	t.Run("Password too short", func(t *testing.T) {

		mockUserService := new(mocks.MockUserService)
		mockUserService.On("Signup", mock.AnythingOfType("*gin.Context"), mock.AnythingOfType("*model.User")).Return(nil)

		rr := httptest.NewRecorder()

		router := gin.Default()

		NewHandler(&Config{
			R:				router,
			UserService:	mockUserService,
		})

		reqBody, err := json.Marshal(gin.H{
			"email": "bob@bob.com",
			"password": "supe",
		})
		assert.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(reqBody))
		assert.NoError(t, err)

		request.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(rr, request)

		assert.Equal(t, 400, rr.Code)
		mockUserService.AssertNotCalled(t, "Signup")

	})

	t.Run("Error returned from UserService", func(t *testing.T) {
		u := &model.User{
			Email: "bob@bob.com",
			Password: "avalidpassword",
		}

		mockUserService := new(mocks.MockUserService)
		mockUserService.On("Signup", mock.AnythingOfType("*gin.Context"), mock.AnythingOfType("*model.User")).Return(apperrors.NewConflict("User Already Exists", u.Email))

		rr := httptest.NewRecorder()

		router := gin.Default()

		NewHandler(&Config{
			R:				router,
			UserService:	mockUserService,
		})

		reqBody, err := json.Marshal(gin.H{
			"email": u.Email,
			"password": u.Password,
		})
		assert.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(reqBody))
		assert.NoError(t, err)

		request.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(rr, request)

		assert.Equal(t, 409, rr.Code)
		mockUserService.AssertExpectations(t)

	})
	
	t.Run("Successful Token Creation", func(t *testing.T) {
		u := &model.User {
			Email: 		"bob@bob.com",
			Password: 	"avalidpassword",
		}

		mockTokenResp := &model.TokenPair{
			IDToken: 		"idToken",
			RefreshToken: 	"refreshToken",
		}

		mockUserService := new(mocks.MockUserService)
		mockTockenService := new(mocks.MockTokenService)

		mockUserService.On("Signup", mock.AnythingOfType("*gin.Context"), u).Return(nil)
		mockTockenService.On("NewPairFromUser", mock.AnythingOfType("*gin.Context"), u, "").Return(mockTokenResp, nil)

		rr := httptest.NewRecorder()

		router := gin.Default()

		NewHandler(&Config{
			R:				router,
			UserService: 	mockUserService,
			TokenService: 	mockTockenService,
		})

		reqBody, err := json.Marshal(gin.H{
			"email": 	u.Email,
			"password": u.Password,
		})
		assert.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(reqBody))
		assert.NoError(t, err)

		request.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(rr, request)

		respBody, err := json.Marshal(gin.H{
			"tokens": mockTokenResp,
		})
		assert.NoError(t, err)

		assert.Equal(t, http.StatusCreated, rr.Code)
		assert.Equal(t, respBody, rr.Body.Bytes())

		mockUserService.AssertExpectations(t)
		mockTockenService.AssertExpectations(t)
	})

	t.Run("Failed Token Creation", func(t *testing.T) {
		u := &model.User {
			Email: 		"bob@bob.com",
			Password: 	"avalidpassword",
		}
		mockErrorResponse := apperrors.NewInternal()

		mockUserService := new(mocks.MockUserService)
		mockTockenService := new(mocks.MockTokenService)

		mockUserService.On("Signup", mock.AnythingOfType("*gin.Context"), u).Return(nil)
		mockTockenService.On("NewPairFromUser", mock.AnythingOfType("*gin.Context"), u, "").Return(nil, mockErrorResponse)

		rr := httptest.NewRecorder()

		router := gin.Default()

		NewHandler(&Config{
			R:				router,
			UserService: 	mockUserService,
			TokenService: 	mockTockenService,
		})

		reqBody, err := json.Marshal(gin.H{
			"email": 	u.Email,
			"password": u.Password,
		})
		assert.NoError(t, err)

		request, err := http.NewRequest(http.MethodPost, "/signup", bytes.NewBuffer(reqBody))
		assert.NoError(t, err)

		request.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(rr, request)

		respBody, err := json.Marshal(gin.H{
			"error": mockErrorResponse,
		})
		assert.NoError(t, err)

		assert.Equal(t, mockErrorResponse.Status(), rr.Code)
		assert.Equal(t, respBody, rr.Body.Bytes())

		mockUserService.AssertExpectations(t)
		mockTockenService.AssertExpectations(t)
	})
}