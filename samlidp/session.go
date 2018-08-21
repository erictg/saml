package samlidp

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"text/template"
	"time"

	"github.com/erictg/saml"
	"github.com/gin-gonic/gin"
	"github.com/erictg/saml/dto"
	"github.com/pkg/errors"
)

var sessionMaxAge = time.Hour

// GetSession returns the *Session for this request.
//
// If the remote user has specified a username and password in the request
// then it is validated against the user database. If valid it sets a
// cookie and returns the newly created session object.
//
// If the remote user has specified invalid credentials then a login form
// is returned with an English-language toast telling the user their
// password was invalid.
//
// If a session cookie already exists and represents a valid session,
// then the session is returned
//
// If neither credentials nor a valid session cookie exist, this function
// sends a login form and returns nil.
func (s *Server) PostSession(c *gin.Context, req *saml.IdpAuthnRequest) (*saml.Session, error) {
	// if we received login credentials then maybe we can create a session

	var userDto dto.LoginDTO

	if err := c.BindJSON(&userDto); err != nil {

		//get user object
		user, err := s.LookupHandler.GetUserFromEmail(userDto.Email)
		if err != nil{
			s.sendLoginForm(c, req, "Invalid username or password")
			return nil, err
		}

		if err := s.Store.Get(fmt.Sprintf("/users/%s", user.GetId()), &user); err != nil {
			s.sendLoginForm(c, req, "Invalid username or password")
			return nil, err
		}

		if ok, err := s.LoginHandler.Authenticate(&user, userDto.Password); !ok || err != nil {
			s.sendLoginForm(c, req, "Invalid username or password")
			return nil, err
		}

		session := &saml.Session{
			ID:             base64.StdEncoding.EncodeToString(randomBytes(32)),
			CreateTime:     saml.TimeNow(),
			ExpireTime:     saml.TimeNow().Add(sessionMaxAge),
			Index:          hex.EncodeToString(randomBytes(32)),
			UserName:       user.GetName(),
			Groups:         user.GetGroups(),
			UserEmail:      user.GetEmail(),
			UserCommonName: user.GetCommonName(),
			UserSurname:    user.GetSurname(),
			UserGivenName:  user.GetGivenName(),
		}
		if err := s.Store.Put(fmt.Sprintf("/sessions/%s", session.ID), &session); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return nil, err
		}

		c.SetCookie("session", session.ID, int(sessionMaxAge.Seconds()), "/", s.Domain, true,true)

		return session, nil
	}else{
		s.sendLoginForm(c, req, "")
		return nil, err
	}

}
func (s *Server) GetSession(c *gin.Context, req *saml.IdpAuthnRequest) (*saml.Session, error) {
	if sessionCookie, err := c.Request.Cookie("session"); err == nil {
		session := &saml.Session{}
		if err := s.Store.Get(fmt.Sprintf("/sessions/%s", sessionCookie.Value), session); err != nil {
			if err == ErrNotFound {
				s.sendLoginForm(c, req, "")
				return nil, err
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return nil, err
		}

		if saml.TimeNow().After(session.ExpireTime) {
			s.sendLoginForm(c, req, "")
			return nil, errors.New("token expired")
		}
		return session, nil
	}else{
		s.sendLoginForm(c, req, "")
		return nil, errors.New("failed to find cookie")
	}
}

// todo make this page better
// sendLoginForm produces a form which requests a username and password and directs the user
// back to the IDP authorize URL to restart the SAML login flow, this time establishing a
// session based on the credentials that were provided.
func (s *Server) sendLoginForm(c *gin.Context, req *saml.IdpAuthnRequest, toast string) {
	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<html>` +
		`<p>{{.Toast}}</p>` +
		`<form method="post" action="{{.URL}}">` +
		`<input type="text" name="user" placeholder="user" value="" />` +
		`<input type="password" name="password" placeholder="password" value="" />` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input type="submit" value="Log In" />` +
		`</form>` +
		`</html>`))
	data := struct {
		Toast       string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Toast:       toast,
		URL:         req.IDP.SSOURL.String(),
		SAMLRequest: base64.StdEncoding.EncodeToString(req.RequestBuffer),
		RelayState:  req.RelayState,
	}

	if err := tmpl.Execute(c.Writer, data); err != nil {
		panic(err)
	}
}

// HandleLogin handles the `POST /login` and `GET /login` forms. If credentials are present
// in the request body, then they are validated. For valid credentials, the response is a
// 200 OK and the JSON session object. For invalid credentials, the HTML login prompt form
// is sent.
func (s *Server) HandlePostLogin(c *gin.Context) {
	session, err := s.PostSession(c, &saml.IdpAuthnRequest{IDP: &s.IDP})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}
	c.JSON(http.StatusOK, session)
}

func (s* Server) HandleGetLogin(c *gin.Context){
	session, err := s.GetSession(c, &saml.IdpAuthnRequest{IDP: &s.IDP})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}
	c.JSON(http.StatusOK, session)
}


// HandleListSessions handles the `GET /sessions/` request and responds with a JSON formatted list
// of session names.
func (s *Server) HandleListSessions(c *gin.Context) {
	sessions, err := s.Store.List("/sessions/")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}

	c.JSON(http.StatusOK, sessions)
}

// HandleGetSession handles the `GET /sessions/:id` request and responds with the session
// object in JSON format.
func (s *Server) HandleGetSession(c *gin.Context) {
	id := c.Param("id")

	session := saml.Session{}
	err := s.Store.Get(fmt.Sprintf("/sessions/%s", id), &session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}
	c.JSON(http.StatusOK, session)
}

// HandleDeleteSession handles the `DELETE /sessions/:id` request. It invalidates the
// specified session.
func (s *Server) HandleDeleteSession(c *gin.Context) {
	id := c.Param("id")

	err := s.Store.Delete(fmt.Sprintf("/sessions/%s", id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		c.Abort()
		return
	}
	c.Status(http.StatusNoContent)
}
