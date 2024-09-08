package types

type APIResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}
