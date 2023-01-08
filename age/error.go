package age

import (
	"encoding/json"
	"errors"
)

var (
	ErrEmpty = errors.New("empty")
)

type Error struct {
	Cause     error
	RootCause error
}

func (e *Error) Error() string {
	if e.RootCause == nil {
		return e.Cause.Error()
	}
	return e.Cause.Error() + ": " + e.RootCause.Error()
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		&struct {
			Error string `json:"error"`
		}{Error: e.Error()})
}
