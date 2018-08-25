package interface_impls

import (
	"github.com/erictg/saml/samlidp"
	"github.com/pkg/errors"
)

type User struct{
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

func (u User) GetId() string {
	return u.Id
}

func (u User) GetName() string {
	return u.Name
}

func (u User) GetPasswordHash() string {
	return u.PasswordHash
}

func (u User) GetSalt() string {
	return u.Salt
}

func (u User) GetGroups() []string {
	return u.Groups
}

func (u User) GetEmail() string {
	return u.Email
}

func (u User) GetCommonName() string {
	return u.CommonName
}

func (u User) GetSurname() string {
	return u.Surname
}

func (u User) GetGivenName() string {
	return u.GivenName
}

func (u User) SetId(id string) {
	u.Id = id
}

func (u User) SetName(name string) {
	u.Name = name
}

func (u User) SetPassword(password string) error {
	u.PasswordHash = password
	return nil
}

func (u User) SetSalt(salt string) {
	u.Salt = salt
}

func (u User) SetGroups(groups []string) {
	u.Groups = groups
}

func (u User) SetEmail(email string) {
	u.Email = email
}

func (u User) SetCommonName(cn string) {
	u.CommonName = cn
}

func (u User) SetSurname(surname string) {
	u.Surname = surname
}

func (u User) SetGivenName(givenName string) {
	u.GivenName = givenName
}

func (u User) GetUser() interface{} {
	return u
}

type AuthenticationProvider struct{

}

func (a AuthenticationProvider) Authenticate(user samlidp.IUser, checkPass string) (bool, error) {
	return user.GetPasswordHash() == checkPass, nil
}

func (a AuthenticationProvider) HashPassword(newPassword string) (newHash string, salt string, err error) {
	return newPassword, "dasdf",nil
}

type LookupProvider struct{
	bob User
	alice User
}

func NewLookupProvider(bob, alice User) LookupProvider{
	return LookupProvider{
		bob: bob,
		alice: alice,
	}
}

func (l LookupProvider) GetUserFromEmail(email string) (samlidp.IUser, error) {
	if email == l.alice.Email{
		return l.alice, nil
	}else if email == l.bob.Email{
		return l.bob, nil
	}else{
		return nil, errors.New("failed to find a user")
	}
}

func (l LookupProvider) GetUserFromId(id string) (samlidp.IUser, error) {
	if id == l.alice.Id{
		return l.alice, nil
	}else if id == l.bob.Id{
		return l.bob, nil
	}else{
		return nil, errors.New("failed to find a user")
	}
}





