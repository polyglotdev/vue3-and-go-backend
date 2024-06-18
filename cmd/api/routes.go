package main

import (
	"net/http"

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

		err = app.writeJSON(w, http.StatusOK, all)
		if err != nil {
			app.errorLog.Println(err)
			return
		}
	})

	mux.Get("/users/add", func(w http.ResponseWriter, r *http.Request) {
		var u = data.User{
			Email:     "you@there.com",
			FirstName: "You",
			LastName:  "There",
			Password:  "password",
		}

		app.infoLog.Println("Adding user...")

		id, err := app.models.User.Insert(u)
		if err != nil {
			app.errorLog.Println(err)
			return
		}

		app.infoLog.Println("Got back id of", id)
		newUser, _ := app.models.User.GetOne(id)
		err = app.writeJSON(w, http.StatusOK, newUser)
		if err != nil {
			app.errorLog.Println(err)
			return
		}
	})

	return mux
}