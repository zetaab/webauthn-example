package main

import (
	"encoding/json"
	"log"
	"strings"

	common "github.com/elisasre/go-common"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthn *webauthn.WebAuthn
var userDB *userdb

func main() {

	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",          // Display Name for your site
		RPID:          "localhost",             // Generally the domain name for your site
		RPOrigin:      "http://localhost:8080", // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	userDB = DB()

	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))
	r.GET("/register/begin/:username", BeginRegistration)
	r.POST("/register/finish/:username", FinishRegistration)
	r.GET("/login/begin/:username", BeginLogin)
	r.POST("/login/finish/:username", FinishLogin)
	r.Use(static.Serve("/", static.LocalFile("./", false)))
	log.Fatal(r.Run())
}

func BeginRegistration(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: "username is empty"})
		c.Abort()
		return
	}

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist, create new user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = NewUser(username, displayName)
		userDB.PutUser(user)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	opt, sessionData, err := webAuthn.BeginRegistration(
		user,
		registerOptions,
	)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	session := sessions.Default(c)
	sessionDataBytes, err := json.Marshal(sessionData)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}
	session.Set("registration", sessionDataBytes)
	err = session.Save()
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}
	c.JSON(200, opt)
}

func FinishRegistration(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: "username is empty"})
		c.Abort()
		return
	}

	// get user
	user, err := userDB.GetUser(username)
	// user doesn't exist
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	session := sessions.Default(c)
	sessionDataBytes := session.Get("registration")
	var sessionData webauthn.SessionData
	// TODO: type assertion check
	err = json.Unmarshal(sessionDataBytes.([]byte), &sessionData)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}
	credential, err := webAuthn.FinishRegistration(user, sessionData, c.Request)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	user.AddCredential(*credential)
	c.String(200, "Registration Success")
}

func BeginLogin(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: "username is empty"})
		c.Abort()
		return
	}
	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(user)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	session := sessions.Default(c)
	sessionDataBytes, err := json.Marshal(sessionData)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}
	session.Set("authentication", sessionDataBytes)
	err = session.Save()
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}
	c.JSON(200, options)
}

func FinishLogin(c *gin.Context) {
	username := c.Param("username")
	if username == "" {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: "username is empty"})
		c.Abort()
		return
	}

	// get user
	user, err := userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	session := sessions.Default(c)
	sessionDataBytes := session.Get("authentication")

	var sessionData webauthn.SessionData
	// TODO: type assertion check
	err = json.Unmarshal(sessionDataBytes.([]byte), &sessionData)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(user, sessionData, c.Request)
	if err != nil {
		c.JSON(400, common.ErrorResponse{Code: 400, Message: err.Error()})
		c.Abort()
		return
	}

	c.String(200, "login success %s", user.name)
}
