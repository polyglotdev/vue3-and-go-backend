package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/polyglotdev/vue-api/internal/data"
)

// routes generates our routes and attaches them to handlers, using the chi router
// note that we return type http.Handler, and not *chi.Mux; since chi.Mux satisfies
// the interface requirements for http.Handler, it makes sense to return the type
// that is part of the standard library.
func (app *application) routes() http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.Recoverer)
	mux.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	mux.Get("/users/login", app.Login)
	mux.Post("/users/login", app.Login)

	mux.Get("/users/all", func(w http.ResponseWriter, r *http.Request) {
		var users data.User
		all, err := users.GetAll()
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		payload := jsonResponse{
			Error:   false,
			Message: "All users retrieved",
			Data:    envelope{"users": all},
		}

		err = app.writeJSON(w, http.StatusOK, payload)
		if err != nil {
			app.errorLog.Println(err)
			return
		}
	})

	mux.Get("/users/add", func(w http.ResponseWriter, r *http.Request) {
		var u = data.User{
			Email:     "dmitri@polyglot.dev",
			FirstName: "Dmitri",
			LastName:  "Johnson",
			Password:  "password",
		}

		app.infoLog.Println("Adding user...")

		id, err := app.models.User.Insert(u)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		app.infoLog.Println("Got User ID of: ", id)
		newUser, _ := app.models.User.GetOne(id)
		err = app.writeJSON(w, http.StatusOK, newUser)
		if err != nil {
			app.errorLog.Println(err)
			return
		}
	})

	mux.Get("/test-generate-token", func(w http.ResponseWriter, r *http.Request) {
		token, err := app.models.User.Token.GenerateToken(2, 60*time.Minute)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		token.Email = "you@there.com"
		token.CreatedAt = time.Now()
		token.UpdatedAt = time.Now()

		payload := jsonResponse{
			Error:   false,
			Message: "Token generated",
			Data:    token,
		}

		if err = app.writeJSON(w, http.StatusOK, payload); err != nil {
			app.errorLog.Println("Error while writing JSON response:", err)
		}
	})

	mux.Get("/test-save-token", func(w http.ResponseWriter, r *http.Request) {
		token, err := app.models.User.Token.GenerateToken(2, 60*time.Minute)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		user, err := app.models.User.GetOne(2)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		token.UserID = user.ID
		token.CreatedAt = time.Now()
		token.UpdatedAt = time.Now()
		app.infoLog.Println("Your token is: ", token.Token)

		err = token.Insert(*token, *user)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		payload := jsonResponse{
			Error:   false,
			Message: "Token generated",
			Data:    token,
		}

		if err = app.writeJSON(w, http.StatusOK, payload); err != nil {
			app.errorLog.Println("Error while writing JSON response:", err)
		}
	})

	mux.Get("/test-validate-token", func(w http.ResponseWriter, r *http.Request) {
		tokenToValidate := r.URL.Query().Get("token")
		valid, err := app.models.User.Token.ValidToken(tokenToValidate)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		var payload jsonResponse
		payload.Error = !valid
		payload.Message = "Token is valid"
		payload.Data = valid

		if err = app.writeJSON(w, http.StatusOK, payload); err != nil {
			app.errorLog.Println("Error while writing JSON response:", err)
		}
	})
	return mux
}
