package main

import (
	"net/http"
	"time"
)

// jsonResponse is the type used for generic JSON responses
// It is used to represent JSON responses that are sent back to the client.
// It has two fields:
//   - error: A boolean indicating whether an error occurred during the request.
//   - message: A string containing a message describing the result of the request.
type jsonResponse struct {
	// Error is a boolean indicating whether an error occurred during the request.
			Error bool `json:"error"`
	// Message is a string containing a message describing the result of the request.
	Message string `json:"message"`

	// Data is a generic field that can be used to store additional data.
	Data interface{} `json:"data,omitempty"`
}

type envelope map[string]interface{}

// Login is the handler used to attempt to log a user into the api
// It expects a JSON object with the following fields:
//   - email: The email address of the user to log in.
//   - password: The password of the user to log in.
//
// It returns a JSON response with the following fields:
//   - error: A boolean indicating whether an error occurred during the login process.
//   - message: A string containing a message describing the result of the login process.
//
// Parameters:
//   - w: The HTTP response writer.
//   - r: The HTTP request.
//
// Returns:
//   - An error if there was an issue with the request or response.
func (app *application) Login(w http.ResponseWriter, r *http.Request) {
	type credentials struct {
		Username string `json:"email"`
		Password string `json:"password"`
	}

	var creds credentials
	var payload jsonResponse

	err := app.readJSON(w, r, &creds)
	if err != nil {
		app.errorLog.Println("Error while reading JSON:", err)
		payload.Error = true
		payload.Message = "invalid json supplied, or json missing entirely"
		_ = app.writeJSON(w, http.StatusBadRequest, payload)
		return
	}

	// TODO authenticate
	app.infoLog.Println(creds.Username, creds.Password)

	// lookup user by email
	user, err := app.models.User.GetByEmail(creds.Username)
	if err != nil {
		app.errorLog.Println("invalid username/password:", err)
		payload.Error = true
		payload.Message = "user not found"
		_ = app.writeJSON(w, http.StatusBadRequest, payload)
		return
	}

	// validate user's password
	validPassword, err := user.PasswordMatches(creds.Password)
	if err != nil || !validPassword {
		app.errorLog.Println("invalid username/password:", err)
		payload.Error = true
		payload.Message = "invalid username/password"
		_ = app.writeJSON(w, http.StatusBadRequest, payload)
		return
	}

	// generate a token
	token, err := app.models.User.Token.GenerateToken(user.ID, 24*time.Hour)
	if err != nil {
		app.errorLog.Println("error generating token:", err)
		payload.Error = true
		payload.Message = "error generating token"
		_ = app.writeJSON(w, http.StatusBadRequest, payload)
		return
	}

	// save to database
	err = app.models.User.Token.Insert(*token, *user)
	if err != nil {
		app.errorLog.Println("error saving token:", err)
		payload.Error = true
		payload.Message = "error saving token"
		_ = app.writeJSON(w, http.StatusBadRequest, payload)
		return
	}

	// send back a response
	payload = jsonResponse{
		Error:   false,
		Message: "Signed in",
		Data:    envelope{"token": token},
	}

	err = app.writeJSON(w, http.StatusOK, payload)
	if err != nil {
		app.errorLog.Println("Error while writing JSON response:", err)
	}
}
