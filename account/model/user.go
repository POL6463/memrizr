package model

import (
	"github.com/google/uuid"
)

type User struct {
	UID			uuid.UUID 	`db:"uid" json:"uid"`
	Email 		string 		`db:"email" json:"emil"`
	Password	string		`db:"password" json:"-"`
	Name		string		`db:"name" json:"name"`
	ImageURL	string 		`db:"image_url" json:"imageUrl"`
	Website		string		`db:"website" json:"website"`
}
