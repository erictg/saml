package samlidp

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/erictg/saml/dto"
)

// IUser represents an abstraction of a stored user. The data here are used to
// populate user once the user has authenticated.
type IUser interface {
	GetId() string
	GetName() string
	GetPasswordHash() string
	GetSalt() string
	GetGroups() []string
	GetEmail() string
	GetCommonName() string
	GetSurname() string
	GetGivenName() string

	SetId(id string)
	SetName(name string)
	SetPassword(password string) error
	SetSalt(salt string)
	SetGroups(groups []string)
	SetEmail(email string)
	SetCommonName(cn string)
	SetSurname(surname string)
	SetGivenName(givenName string)

	GetUser() interface{}
}

// HandleListUsers handles the `GET /users/` request and responds with a JSON formatted list
// of user names.
func (s *Server) HandleListUsers(c *gin.Context) {
	users, err := s.Store.List("/users/")
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK,struct {
		Users []string `json:"users"`
	}{Users: users})
}

type serializeUser struct{
	Id				string		`json:"id"`
	Name			string		`json:"name"`
	PasswordHash	string		`json:"password_hash"`
	Salt			string		`json:"salt"`
	Groups			[]string	`json:"groups"`
	Email			string		`json:"email"`
	CommonName		string		`json:"common_name"`
	Surname			string		`json:"surname"`
	GivenName		string		`json:"given_name"`
}

// HandleGetUser handles the `GET /users/:id` request and responds with the user object in JSON
// format. The HashedPassword field is excluded.
func (s *Server) HandleGetUser(c *gin.Context) {
	var user serializeUser
	err := s.Store.Get(fmt.Sprintf("/users/%s", c.Param("id")), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, user)
}

// HandlePutUser handles the `PUT /users/:id` request. It accepts a JSON formatted user object in
// the request body and stores it. If the PlaintextPassword field is present then it is hashed
// and stored in HashedPassword. If the PlaintextPassword field is not present then
// HashedPassword retains it's stored value.
func (s *Server) HandlePutUser(c *gin.Context) {
	var userDto dto.UpdateUserDTO
	if err := c.BindJSON(&userDto); err != nil {
		s.logger.Printf("ERROR: %s", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	user, err := s.LookupHandler.GetUserFromId(userDto.Id)

	user.SetName(c.Param("id"))

	if userDto.NewPassword != nil {
		err := user.SetPassword(*userDto.NewPassword)

		if err != nil {
			s.logger.Printf("ERROR: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}
	}

	err = s.Store.Put(fmt.Sprintf("/users/%s", userDto.Id), &user)
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}
	c.Status(http.StatusNoContent)
}

// HandleDeleteUser handles the `DELETE /users/:id` request.
func (s *Server) HandleDeleteUser(c *gin.Context) {
	err := s.Store.Delete(fmt.Sprintf("/users/%s", c.Param("id")))
	if err != nil {
		s.logger.Printf("ERROR: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}
	c.Status(http.StatusNoContent)
}
