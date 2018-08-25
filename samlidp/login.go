package samlidp

// IAuthentication interface to login
type IAuthentication interface {
	// Authenticate the user
	Authenticate(user IUser, checkPass string) (bool, error)

	// HashPassword set password (should hash and salt)
	HashPassword(newPassword string) (newHash string, salt string, err error)
}
