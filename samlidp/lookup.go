package samlidp

// ILookup interface to lookup users
type ILookup interface {
	// GetUserFromEmail lookup by email
	GetUserFromEmail(email string) (IUser, error)

	// GetUserFromId lookup by id
	GetUserFromId(id string) (IUser, error)
}
