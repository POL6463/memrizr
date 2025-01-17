package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jacobsngoodwin/memrizr/account/handler"
	"github.com/jacobsngoodwin/memrizr/account/repository"
	"github.com/jacobsngoodwin/memrizr/account/service"
)

func inject(d *dataSources) (*gin.Engine, error) {
	log.Println("Injecting data sources")

	/*
	* repotory layer
	*/
	userRepository := repository.NewUserRepository(d.DB)
	tokenRepository := repository.NewTokenRepository(d.RedisClient)

	bucketName := os.Getenv("GC_IMAGE_BUCKET")
	imageRepository := repository.NewImageRepository(d.StorageClient, bucketName)

	//service layer
	userService := service.NewUserService(&service.USConfig{
		UserRepository: userRepository,
		ImageRepository: imageRepository,
	})

	privKeyFile := os.Getenv("PRIV_KEY_FILE")
	priv, err := ioutil.ReadFile(privKeyFile)

	if err != nil {
		return nil, fmt.Errorf("could not read private key pem file: %w", err)
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(priv)

	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	pubKeyFile := os.Getenv("PUB_KEY_FILE")
	pub, err := ioutil.ReadFile(pubKeyFile)

	if err != nil {
		return nil, fmt.Errorf("could not read private key pem file: %w", err)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pub)

	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	refreshSecret := os.Getenv("REFRESH_SECRET")

	idTokenExp := os.Getenv("ID_TOKEN_EXP")
	refreshTokenExp := os.Getenv("REFRESH_TOKEN_EXP")

	idExp, err := strconv.ParseInt(idTokenExp, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse ID_TOKEN_EXP as int: %w", err)
	}

	refreshExp, err := strconv.ParseInt(refreshTokenExp, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse REFRESH_TOKEN_EXP as int: %w", err)
	}

	tokenService := service.NewTokenService(&service.TSConfig{
		TokenRepository: tokenRepository,
		PrivKey: privKey,
		PubKey: pubKey,
		RefreshSecret: refreshSecret,
		IDExpiratonSecs: idExp,
		RefreshExpirationSecs: refreshExp,
	})

	router := gin.Default()

	baseURL := os.Getenv("ACCOUNT_API_URL")

	handlerTimeout := os.Getenv("HANDLER_TIMEOUT")
	ht, err := strconv.ParseInt(handlerTimeout, 0, 64)
	if err != nil {
		return nil, fmt.Errorf("could not parse HANDLER_TIMEOUT as int: %w", err)
	}

	handler.NewHandler(&handler.Config{
		R: router,
		UserService: userService,
		TokenService: tokenService,
		BaseURL: baseURL,
		TimeoutDuration: time.Duration(time.Duration(ht) * time.Second),
	})

	return router, nil
}