package dto

type LoginDTO struct{
	Password	string		`json:"password"`
	Email		string		`json:"email"`
}

type UpdateUserDTO struct{
	Id				string		`json:"id"`
	Name			*string		`json:"name"`
	NewPassword		*string		`json:"new_password"`

}