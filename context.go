package nassh

import "context"

type contextKey string

const (
	ctxUserID       contextKey = "user-id"
	ctxLoginSession contextKey = "login-session"
	ctxSSHSession   contextKey = "ssh-session"
	ctxRemoteAddr   contextKey = "remote-addr"
)

// UserID returns the unique user identity from the given context
func UserID(ctx context.Context) (string, bool) {
	u, ok := ctx.Value(ctxUserID).(string)
	return u, ok
}

// LoginSessionID returns the identifier of the login session from the given
// context
func LoginSessionID(ctx context.Context) (string, bool) {
	l, ok := ctx.Value(ctxLoginSession).(string)
	return l, ok
}

// SSHSessionID returns the identifier of the relay session
func SSHSessionID(ctx context.Context) (string, bool) {
	u, ok := ctx.Value(ctxSSHSession).(string)
	return u, ok
}

// RemoteAddr returns the remote address of the caller
func RemoteAddr(ctx context.Context) (string, bool) {
	r, ok := ctx.Value(ctxRemoteAddr).(string)
	return r, ok
}
