package service

import (
	"context"
	"log"
	"mime/multipart"
	"net/url"
	"path"

	"github.com/google/uuid"
	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/apperrors"
)

type userService struct {
	UserRepository model.UserRepository
	ImageRepository model.ImageRepository
}

type USConfig struct {
	UserRepository model.UserRepository
	ImageRepository model.ImageRepository
}

func NewUserService(c *USConfig) model.UserService {
	return &userService {
		UserRepository: c.UserRepository,
		ImageRepository: c.ImageRepository,
	}
}
func (s *userService) Get(ctx context.Context, uid uuid.UUID) (*model.User ,error) {
	u, err := s.UserRepository.FindByID(ctx, uid)

	return u, err
}

func (s *userService) Signup(ctx context.Context, u *model.User) error {
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

func (s *userService) Signin(ctx context.Context, u *model.User) error {
	uFetched, err := s.UserRepository.FindByEmail(ctx, u.Email)

	if err != nil {
		return apperrors.NewAuthorization("Invalid email and password combination")
	}

	match, err := comparePasswords(uFetched.Password, u.Password)

	if err != nil {
		return apperrors.NewInternal()
	}

	if !match {
		return apperrors.NewAuthorization("Invalid email and password combination")
	}

	*u = *uFetched
	return nil
}

func (s *userService) UpdateDetails(ctx context.Context, u *model.User) error {
	err := s.UserRepository.Update(ctx, u)

	if err != nil {
		return err
	}

	return nil
}

func (s *userService) SetProfileImage(
	ctx context.Context,
	uid uuid.UUID,
	imageFileHeader *multipart.FileHeader,
) (*model.User, error) {
	u, err := s.UserRepository.FindByID(ctx, uid)

	if err != nil {
		return nil, err
	}

	objName, err := objNameFromURL(u.ImageURL)

	if err != nil {
		return nil, err
	}

	imageFile, err := imageFileHeader.Open()
	if err != nil {
		log.Printf("Failed to open image file: %v\n", err)
		return nil, err
	}

	imageURL, err := s.ImageRepository.UpdateProfile(ctx, objName, imageFile)	

	if err != nil {
		log.Printf("Unable to upload image to cloud provider: %v\n", err)
		return nil, err
	}

	updatedUser, err := s.UserRepository.UpdateImage(ctx, uid, imageURL)

	if err != nil {
		log.Printf("Unable to update imageURL: %v\n", err)
		return nil, err
	}

	return updatedUser, nil
}

func objNameFromURL(imageURL string) (string, error) {

	if imageURL == "" {
		objID, _ := uuid.NewRandom()
		return objID.String(), nil
	}

	urlPath, err := url.Parse(imageURL)

	if err != nil {
		log.Printf("Failed to parse objectNAme from imageURL: %v\n", imageURL)
		return "", apperrors.NewInternal()
	}

	return path.Base(urlPath.Path), nil
}