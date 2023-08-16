package socket

import (
	"errors"
	"strings"
)

var (
	ErrTCPPrefix = errors.New(
		"tcp front should be specified by proto prefix 'tcp://'")
	ErrUDPPrefix = errors.New(
		"udp front should be specified by proto prefix 'udp://'")
	ErrMulticastAddr = errors.New("invalid multicast addr")
)

// HandlerError socket handler error
type HandlerError interface {
	error

	IsRecoverable() bool
}

type recoverableError struct {
	error
}

func (er *recoverableError) IsRecoverable() bool {
	return true
}

// NewRecoverableError create new recoverable error
func NewRecoverableError(err error) error {
	return &recoverableError{err}
}

// StackedHandlerError multiple errors
type StackedHandlerError struct {
	errors []error
}

func (err *StackedHandlerError) Error() string {
	messages := make([]string, len(err.errors))

	for idx, err := range err.errors {
		messages[idx] = err.Error()
	}

	return strings.Join(messages, "\n")
}

// IsRecoverable check if stacked errors is recoverable
func (err *StackedHandlerError) IsRecoverable() bool {
	for _, e := range err.errors {
		if v, ok := e.(HandlerError); !ok || !v.IsRecoverable() {
			return false
		}
	}

	return true
}

// HasErrors check if has errors
func (err *StackedHandlerError) HasErrors() bool {
	return len(err.errors) > 0
}

// AppendErr append multiple errors
func (err *StackedHandlerError) AppendErr(e error) {
	if e != nil {
		err.errors = append(err.errors, e)
	}
}
