// Package samlidp a rudimentary SAML identity provider suitable for
// testing or as a starting point for a more complex service.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"net/url"
	"sync"

	"github.com/erictg/saml"
	"github.com/erictg/saml/logger"
	"github.com/gin-gonic/gin"
)

type ILogin interface {
	Authenticate(user *IUser, checkPass string) (bool, error)
}

type ILookup interface {
	GetUserFromEmail(email string) (IUser, error)
	GetUserFromId(id string) (IUser, error)
}

// Options represent the parameters to New() for creating a new IDP server
type Options struct {
	URL         url.URL
	Key         crypto.PrivateKey
	Logger      logger.Interface
	Certificate *x509.Certificate
	Store       Store
	LoginHandler	ILogin
	LookupHandler	ILookup
}

// Server represents an IDP server. The server provides the following URLs:
//
//     /metadata     - the SAML metadata
//     /sso          - the SAML endpoint to initiate an authentication flow
//     /login        - prompt for a username and password if no session established
//     /login/:shortcut - kick off an IDP-initiated authentication flow
//     /services     - RESTful interface to Service objects
//     /users        - RESTful interface to User objects
//     /sessions     - RESTful interface to Session objects
//     /shortcuts    - RESTful interface to Shortcut objects
type Server struct {
	http.Handler
	idpConfigMu      sync.RWMutex // protects calls into the IDP
	logger           logger.Interface
	serviceProviders map[string]*saml.EntityDescriptor
	IDP              saml.IdentityProvider // the underlying IDP
	Store            Store                 // the data store
	LoginHandler	ILogin
	LookupHandler	ILookup
	Domain			string
}

// New returns a new Server
func New(opts Options) (*Server, error) {
	metadataURL := opts.URL
	metadataURL.Path = metadataURL.Path + "/metadata"
	ssoURL := opts.URL
	ssoURL.Path = ssoURL.Path + "/sso"
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	s := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		IDP: saml.IdentityProvider{
			Key:         opts.Key,
			Logger:      logr,
			Certificate: opts.Certificate,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
		},
		logger: logr,
		Store:  opts.Store,
	}

	s.IDP.SessionProvider = s
	s.IDP.ServiceProviderProvider = s

	if err := s.initializeServices(); err != nil {
		return nil, err
	}
	s.InitializeHTTP()
	return s, nil
}

// InitializeHTTP sets up the HTTP handler for the server. (This function
// is called automatically for you by New, but you may need to call it
// yourself if you don't create the object using New.)
func (s *Server) InitializeHTTP() *gin.Engine{
	e := gin.New()

	e.GET("/metadata", func(c *gin.Context) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeMetadata(c)
	})
	e.POST("/sso", func(c *gin.Context) {
		s.idpConfigMu.RLock()
		defer s.idpConfigMu.RUnlock()
		s.IDP.ServeSSO(c)
	})

	e.POST("/login", s.HandlePostLogin)
	e.GET("/login", s.HandlePostLogin)
	e.GET("/login/:shortcut", s.HandleIDPInitiated)
	//e.GET("/login/:shortcut/*", s.HandleIDPInitiated)

	e.GET("/services/", s.HandleListServices)
	e.GET("/services/:id", s.HandleGetService)
	e.PUT("/services/:id", s.HandlePutService)
	e.POST("/services/:id", s.HandlePutService)
	e.DELETE("/services/:id", s.HandleDeleteService)

	e.GET("/users/", s.HandleListUsers)
	e.GET("/users/:id", s.HandleGetUser)
	e.PUT("/users/:id", s.HandlePutUser)
	e.DELETE("/users/:id", s.HandleDeleteUser)

	e.GET("/sessions/", s.HandleListSessions)
	e.GET("/sessions/:id", s.HandleGetSession)
	e.DELETE("/sessions/:id", s.HandleDeleteSession)

	e.GET("/shortcuts/", s.HandleListShortcuts)
	e.GET("/shortcuts/:id", s.HandleGetShortcut)
	e.PUT("/shortcuts/:id", s.HandlePutShortcut)
	e.DELETE("/shortcuts/:id", s.HandleDeleteShortcut)

	return e
}
