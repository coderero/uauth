package types

type UserAccessFilter struct {
	// Every filters all users
	Every bool `json:"-" query:"-"`
	// Active filters the active users
	Active bool `json:"active" query:"active"`
	// Deleted filters the deleted users
	Deleted bool `json:"deleted" query:"deleted"`
	// Admin filters the admin users
	Admin bool `json:"admin" query:"admin"`
	// Superadmin filters the superadmin users
	Superadmin bool `json:"superadmin" query:"superadmin"`
	// Pagination
	Page int `json:"page" query:"page"`
	// Limit
	Limit int `json:"limit" query:"limit"`
}

func (u *UserAccessFilter) Empty() bool {
	return !u.Every && !u.Active && !u.Deleted && !u.Admin && !u.Superadmin && u.Page == 0 && u.Limit == 0
}
