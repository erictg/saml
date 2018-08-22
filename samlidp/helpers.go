package samlidp

import "fmt"

func CreateUserKey(u IUser) string{
	return fmt.Sprintf("/users/%s", u.GetId())
}
