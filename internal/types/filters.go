package types

type UserAccessFilter struct {
	// Every filters all users
	Every bool `query:"-"`
	// Active filters the active users
	Active string `query:"active"`
	// Deleted filters the deleted users
	Deleted string `query:"deleted"`
	// Admin filters the admin users
	Admin string `query:"admin"`
	// Superadmin filters the superadmin users
	Superadmin string `query:"superadmin"`
	// SortBy sorts the users by the given field
	SortBy string `query:"sort_by"`
	// Order orders the users by the given order
	Order string `query:"order"`
	// Pagination
	Page int `query:"page"`
	// Limit
	Limit int `query:"limit"`
}

func (u *UserAccessFilter) Empty() bool {
	return u.Active == "" && u.Deleted == "" && u.Admin == "" && u.Superadmin == "" && u.SortBy == "" && u.Order == "" && u.Page == 0 && u.Limit == 0
}
