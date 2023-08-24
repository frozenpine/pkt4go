package errors

import (
	"errors"
)

var (
	ErrRecoverable = errors.New("recoverable err occoured")
)

func New(msg string) error {
	return errors.New(msg)
}

func Join(err ...error) error {
	return errors.Join(err...)
}

func Unwrap(err error) error {
	return errors.Unwrap(err)
}

func As(err error, target any) bool {
	return errors.As(err, target)
}

func Is(err, target error) bool {
	return errors.Is(err, target)
}

func NewRecoverable(msg string) error {
	return errors.Join(ErrRecoverable, New(msg))
}
