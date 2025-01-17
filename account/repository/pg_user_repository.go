package repository

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/jacobsngoodwin/memrizr/account/model"
	"github.com/jacobsngoodwin/memrizr/account/model/apperrors"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type pgUserRepository struct {
	DB *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) model.UserRepository {
	return &pgUserRepository {
		DB: db,
	}
}

func (r *pgUserRepository) Create(ctx context.Context, u *model.User) error {
	query := "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *"

	if err := r.DB.GetContext(ctx, u, query, u.Email, u.Password); err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code.Name() == "unique_violation" {
			log.Printf("could not create a user with email: %v. Reason: %v\n", u.Email, err.Code.Name())
			return apperrors.NewConflict("email", u.Email)
		}

		log.Printf("Could not create a user with email: %v. Reason: %v\n", u.Email, err)
		return apperrors.NewInternal()
	}
	return nil
}

func (r *pgUserRepository) FindByID(ctx context.Context, uid uuid.UUID) (*model.User, error) {
	user := &model.User{}

	query := "SELECT * FROM users WHERE uid=$1"

	if err := r.DB.GetContext(ctx, user, query, uid); err != nil {
		return user, apperrors.NewNotFound("uid", uid.String())
	}

	return user, nil
}

func (r *pgUserRepository) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	user := &model.User{}

	query := "SELECT * FROM users WHERE email=$1"

	if err := r.DB.GetContext(ctx, user, query, email); err != nil {
		return user, apperrors.NewNotFound("email", email)
	}

	return user, nil
}

func (r *pgUserRepository) UpdateImage(ctx context.Context, uid uuid.UUID, imageURL string) (*model.User, error) {
	query := `
		UPDATE users
		SET image_url = $2
		WHERE uid = $1
		RETURNING *;
	`

	u := &model.User{}

	err := r.DB.GetContext(ctx, u, query, uid, imageURL)

	if err != nil {
		log.Printf("Error updating image_url in database: %v\n", err)
		return nil, apperrors.NewInternal()
	}

	return u, nil
}
