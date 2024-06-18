package data

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const dbTimeout = time.Second * 3

var db *sql.DB

// New is the function used to create an instance of the data package. It returns the type
// Model, which embeds all of the types we want to be available to our application.
func New(dbPool *sql.DB) Models {
	db = dbPool

	return Models{
		User:  User{},
		Token: Token{},
	}
}

// Models represents the data models for the application.
type Models struct {
	// User is the data model for a User.
	User User
	// Token is the data model for a Token.
	Token Token
}

// User represents a user in the database.
type User struct {
	// ID is the primary key for the user.
	ID int `json:"id"`
	// Email is the email address for the user.
	Email string `json:"email"`
	// FirstName is the first name for the user.
	FirstName string `json:"first_name,omitempty"`
	// LastName is the last name for the user.
	LastName string `json:"last_name,omitempty"`
	// Password is the password for the user.
	Password string `json:"password"`
	// CreatedAt is the time the user was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the time the user was last updated.
	UpdatedAt time.Time `json:"updated_at"`
	// Token is the token for the user.
	Token Token `json:"token"`
}

// GetAll returns a slice of all users, sorted by last name
// It returns in a slice of type User and an error.
//
// Parameters:
// - none
//
// Returns:
// - []*User: a slice of type User
// - error: an error
func (u *User) GetAll() ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users order by last_name`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User

	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.FirstName,
			&user.LastName,
			&user.Password,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		users = append(users, &user)
	}

	return users, nil
}

// GetByEmail takes in a email of type string and returns a pointer to the User model and an error.
//
// Parameters:
//
// - email: string
//
// Returns:
//
// - *User: a pointer to the User model
// - error: an error
func (u *User) GetByEmail(email string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where email = $1`

	var user User
	row := db.QueryRowContext(ctx, query, email)

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetOne returns one user by id.
//
// Parameters:
//
// - id: int: the id of the user
//
// Returns:
//
// - *User: a pointer to the User model
// - error: an error
func (u *User) GetOne(id int) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where id = $1`

	var user User
	row := db.QueryRowContext(ctx, query, id)

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Update updates one user in the database, using the information stored in the receiver u.
//
// Parameters:
//
// - none
//
// Returns:
//
// - error: an error
func (u *User) Update() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	stmt := `update users set
		email = $1,
		first_name = $2,
		last_name = $3,
		updated_at = $4
		where id = $5
	`

	_, err := db.ExecContext(ctx, stmt,
		u.Email,
		u.FirstName,
		u.LastName,
		time.Now(),
		u.ID,
	)

	if err != nil {
		return err
	}

	return nil
}

// Delete deletes one user from the database, by ID.
//
// Parameters:
//
// - none
//
// Returns:
//
// - error: an error
func (u *User) Delete() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	stmt := `delete from users where id = $1`

	_, err := db.ExecContext(ctx, stmt, u.ID)
	if err != nil {
		return err
	}

	return nil
}

// Insert inserts a new user into the database, and returns the ID of the newly inserted row.
//
// Parameters:
//
// - user: User: the user to insert
//
// Returns:
//
// - int: the id of the newly inserted row
// - error: an error
func (u *User) Insert(user User) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 12)
	if err != nil {
		return 0, err
	}

	var newID int
	stmt := `insert into users (email, first_name, last_name, password, created_at, updated_at)
		values ($1, $2, $3, $4, $5, $6) returning id`

	err = db.QueryRowContext(ctx, stmt,
		user.Email,
		user.FirstName,
		user.LastName,
		hashedPassword,
		time.Now(),
		time.Now(),
	).Scan(&newID)

	if err != nil {
		return 0, err
	}

	return newID, nil
}

// ResetPassword resets a user's password.
//
// Parameters:
//
// - password: string: the new password for the user
//
// Returns:
//
// - error: an error
func (u *User) ResetPassword(password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}

	stmt := `update users set password = $1 where id = $2`
	_, err = db.ExecContext(ctx, stmt, hashedPassword, u.ID)
	if err != nil {
		return err
	}

	return nil
}

// PasswordMatches uses Go's bcrypt package to compare a user supplied password with the hash we have stored for a given user in the database. If the password and hash match, we return true; otherwise, we return false.
//
// Parameters:
//
// - plainText: string: the plain text password to compare with the hash
//
// Returns:
//
// - bool: true if the password matches the hash, false otherwise
func (u *User) PasswordMatches(plainText string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plainText))

	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			// invalid password
			return false, nil
		default:
			return false, err
		}
	}

	return true, nil
}

// Token is the data structure for any token in the database. Note that
// we do not send the TokenHash (a slice of bytes) in any exported JSON.
type Token struct {
	// ID is the primary key for the token.
	ID int `json:"id"`
	// UserID is the foreign key for the user.
	UserID int `json:"user_id"`
	// Email is the email address for the user.
	Email string `json:"email"`
	// Token is the token for the user.
	Token string `json:"token"`
	// TokenHash is the hash of the token.
	TokenHash []byte `json:"-"`
	// CreatedAt is the time the token was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the time the token was last updated.
	UpdatedAt time.Time `json:"updated_at"`
	// Expiry is the time the token expires.
	Expiry time.Time `json:"expiry"`
}

// GetByToken takes a plain text token string, and looks up the full token from
// the database. It returns a pointer to the Token model.
//
// Parameter:
// - plainText: string: the plain text token to look up
//
// Returns:
// - *Token: a pointer to the Token model
// - error: an error
func (t *Token) GetByToken(plainText string) (*Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, user_id, email, token, token_hash, created_at, updated_at, expiry
			from tokens where token = $1`

	var token Token

	row := db.QueryRowContext(ctx, query, plainText)
	err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.Email,
		&token.Token,
		&token.TokenHash,
		&token.CreatedAt,
		&token.UpdatedAt,
		&token.Expiry,
	)

	if err != nil {
		return nil, err
	}

	return &token, nil
}

// GetUserForToken takes a token parameter, and uses the UserID field from that parameter
// to look a user up by id. It returns a pointer to the user model.
//
// Parameter:
// - token: Token: the token to look up
//
// Returns:
// - *User: a pointer to the User model
// - error: an error
func (t *Token) GetUserForToken(token Token) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	query := `select id, email, first_name, last_name, password, created_at, updated_at from users where id = $1`

	var user User
	row := db.QueryRowContext(ctx, query, token.UserID)

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Password,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GenerateToken generates a secure token of exactly 26 characters in length and returns it.
//
// Parameter:
// - userID: int: the id of the user to generate the token for
// - ttl: time.Duration: the time to live for the token
//
// Returns:
// - *Token: a pointer to the Token model
// - error: an error
func (t *Token) GenerateToken(userID int, ttl time.Duration) (*Token, error) {
	token := &Token{
		UserID: userID,
		Expiry: time.Now().Add(ttl),
	}

	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	token.Token = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(token.Token))
	token.TokenHash = hash[:]

	return token, nil
}

// AuthenticateToken takes the full http request, extracts the authorization header, takes the plain text token from that header and looks up the associated token entry in the database, and then finds the user associated with that token. If the token is valid and a user is found, the user is returned; otherwise, it returns an error.
//
// Parameter:
// - r: *http.Request: the http request
//
// Returns:
// - *User: a pointer to the User model
// - error: an error
func (t *Token) AuthenticateToken(r *http.Request) (*User, error) {
	// get the authorization header
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		return nil, errors.New("no authorization header received")
	}

	// get the plain text token from the header
	headerParts := strings.Split(authorizationHeader, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return nil, errors.New("no valid authorization header received")
	}

	token := headerParts[1]

	// make sure the token is of the correct length
	if len(token) != 26 {
		return nil, errors.New("token wrong size")
	}

	// get the token from the database, using the plain text token to find it
	tkn, err := t.GetByToken(token)
	if err != nil {
		return nil, errors.New("no matching token found")
	}

	// make sure the token has not expired
	if tkn.Expiry.Before(time.Now()) {
		return nil, errors.New("expired token")
	}

	// get the user associated with the token
	user, err := t.GetUserForToken(*tkn)
	if err != nil {
		return nil, errors.New("no matching user found")
	}

	return user, nil
}

// Insert inserts a token into the database.
//
// Parameter:
// - token: Token: the token to insert
// - u: User: the user to associate with the token
//
// Returns:
// - error: an error
func (t *Token) Insert(token Token, u User) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	// delete any existing tokens
	stmt := `delete from tokens where user_id = $1`
	_, err := db.ExecContext(ctx, stmt, token.UserID)
	if err != nil {
		return err
	}

	// we assign the email value, just to be safe, in case it was
	// not done in the handler that calls this function
	token.Email = u.Email

	// insert the new token
	stmt = `insert into tokens (user_id, email, token, token_hash, created_at, updated_at, expiry)
		values ($1, $2, $3, $4, $5, $6, $7)`

	_, err = db.ExecContext(ctx, stmt,
		token.UserID,
		token.Email,
		token.Token,
		token.TokenHash,
		time.Now(),
		time.Now(),
		token.Expiry,
	)
	if err != nil {
		return err
	}

	return nil
}

// DeleteByToken deletes a token, by plain text token.
//
// Parameter:
// - plainText: string: the plain text token to delete
//
// Returns:
// - error: an error
func (t *Token) DeleteByToken(plainText string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()

	stmt := `delete from tokens where token = $1`

	_, err := db.ExecContext(ctx, stmt, plainText)
	if err != nil {
		return err
	}

	return nil
}

// ValidToken checks that a given token is valid; in order to be valid, the token must exist in the database, the associated user must exist in the database, and the token must not have expired.
//
// Parameter:
// - plainText: string: the plain text token to check
//
// Returns:
// - bool: true if the token is valid, false otherwise
// - error: an error
func (t *Token) ValidToken(plainText string) (bool, error) {
	token, err := t.GetByToken(plainText)
	if err != nil {
		return false, errors.New("no matching token found")
	}

	_, err = t.GetUserForToken(*token)
	if err != nil {
		return false, errors.New("no matching user found")
	}

	if token.Expiry.Before(time.Now()) {
		return false, errors.New("expired token")
	}

	return true, nil
}
