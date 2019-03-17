package nassh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

const (
	bsidLength  = 16
	sessionName = "nassh-session"
)

// TODO: Determine or leave configurable
const inactivityDuration = 60 * time.Second

// https://chromium.googlesource.com/apps/libapps/+show/master/nassh/doc/relay-protocol.md

// Relay is a server implementation of the nassh relay protocol.
type Relay struct {
	// Logger to output information to. If not set, it will be initialized to a
	// null logger.
	Logger logrus.FieldLogger
	// Dialer is called to establish the connection to the backend. If not set,
	// the host:port is dialed with a default net.Dialer
	Dialer func(ctx context.Context, add string) (io.ReadWriteCloser, error)

	// HTTPSession is a HTTP session store. It is used to track state across
	// calls. It should be resistent to tampering, to ensure sessions are not
	// spoofed. If not set, it will be initialized to a new cookie store with a
	// random secret on first use.
	HTTPSession sessions.Store

	sessions   map[string]*session
	sessionsMu sync.Mutex

	once sync.Once
}

func (r *Relay) init() {
	r.once.Do(func() {
		if r.HTTPSession == nil {
			r.HTTPSession = sessions.NewCookieStore([]byte(securecookie.GenerateRandomKey(64)))
		}
		if r.Logger == nil {
			r.Logger, _ = test.NewNullLogger()
		}
	})
}

// StartSession should be called at the end of the authentication flow that was
// initialized by a call to /cookie . userID corresponds to a unique identifier
// for the user, for tracking. loginSessID can track the auth session in use,
// for referencing later on. The values of ext, path, version, and method should
// correspond to the query values for the original /cookie call. It should be
// provided an unused ResponseWriter
func (r *Relay) StartSession(w http.ResponseWriter, req *http.Request, userID, loginSessID, ext, path, version, method string) {
	r.init()

	if ext == "" || path == "" {
		http.Error(w, "ext and path are required params", http.StatusBadRequest)
		return
	}
	if version != "" && version != "2" {
		// TODO - we're not really supporting v2 properly
		http.Error(w, "only version 2 is supported", http.StatusBadRequest)
		return
	}

	sess, err := r.HTTPSession.Get(req, sessionName)
	if err != nil {
		r.Logger.WithError(err).Error("error fetching session")
		http.Error(w, "error fetching session", http.StatusInternalServerError)
		return
	}

	sess.Values["userID"] = userID
	sess.Values["loginSessID"] = loginSessID

	if err := sess.Save(req, w); err != nil {
		r.Logger.WithError(err).Error("error saving session")
		http.Error(w, "error saving session", http.StatusInternalServerError)
		return
	}

	if method == "" {
		http.Redirect(w, req, fmt.Sprintf("chrome-extension://%s/%s#anonymous@%s", ext, path, req.Host), http.StatusFound)
	} else if method == "js-redirect" {
		fmt.Fprintf(w, "<script>window.location.href = \"chrome://%s/%s\";</script>", ext, path)
	} else {
		http.Error(w, "only js-redirect supported", http.StatusBadRequest)
		return
	}
	// TODO - render redir doc https://chromium.googlesource.com/apps/libapps/+show/c4b90ef4973513b8e9052f0cff56e8717dc9faf9/nassh/doc/relay-protocol.md#147
}

// ProxyHandler starts the remote connection. Serve at /proxy
// https://chromium.googlesource.com/apps/libapps/+show/c4b90ef4973513b8e9052f0cff56e8717dc9faf9/nassh/doc/relay-protocol.md#153
func (r *Relay) ProxyHandler(w http.ResponseWriter, req *http.Request) {
	r.init()

	host := req.URL.Query().Get("host")
	port := req.URL.Query().Get("port")
	if host == "" || port == "" {
		http.Error(w, "host and port are required params", http.StatusBadRequest)
		return
	}

	sess, err := r.HTTPSession.Get(req, sessionName)
	if err != nil {
		r.Logger.WithError(err).Error("error fetching session")
		http.Error(w, "error fetching session", http.StatusInternalServerError)
		return
	}

	ui, uok := sess.Values["userID"]
	li, lok := sess.Values["loginSessID"]
	if !uok || !lok {
		r.Logger.WithError(err).Error("session missing required information")
		http.Error(w, "session missing required information", http.StatusBadRequest)
		return
	}
	userID := ui.(string)
	loginSessID := li.(string)

	bsid := make([]byte, bsidLength)
	if _, err := rand.Read(bsid); err != nil {
		r.Logger.WithError(err).Error("error generating session ID")
		http.Error(w, "error generating session ID", http.StatusInternalServerError)
		return
	}
	sid := hex.EncodeToString(bsid)

	ctx := context.WithValue(req.Context(), ctxUserID, userID)
	ctx = context.WithValue(ctx, ctxLoginSession, loginSessID)
	ctx = context.WithValue(ctx, ctxSSHSession, sid)
	ctx = context.WithValue(ctx, ctxRemoteAddr, req.RemoteAddr)

	var conn io.ReadWriteCloser
	if r.Dialer != nil {
		conn, err = r.Dialer(ctx, net.JoinHostPort(host, port))
	} else {
		conn, err = (&net.Dialer{}).DialContext(req.Context(), "tcp", net.JoinHostPort(host, port))
	}
	if err != nil {
		r.Logger.WithError(err).WithFields(logrus.Fields{
			"host": host,
			"port": port,
		}).Warn("error establishing connection to server")

		http.Error(w, "error establishing connection to server", http.StatusInternalServerError)
		return
	}

	afterCloseFunc := func() {
		r.Logger.WithField("sid", sid).Info("closed")
		r.deleteSession(sid)
	}
	s := newSession(r.Logger.WithField("sid", sid), conn, inactivityDuration, afterCloseFunc)
	r.setSession(sid, s)
	s.Start()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", req.Header.Get("origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// response is plain text, query string that will be passed to /connect
	fmt.Fprintf(w, "%s", sid)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// ConnectHandler handles the /connect from the client
// https://chromium.googlesource.com/apps/libapps/+show/c4b90ef4973513b8e9052f0cff56e8717dc9faf9/nassh/doc/relay-protocol.md#178
func (r *Relay) ConnectHandler(w http.ResponseWriter, req *http.Request) {
	// Find session
	sid := req.URL.Query().Get("sid")
	if sid == "" {
		http.Error(w, "no session id provided", http.StatusBadRequest)
		return
	}

	sess, ok := r.getSession(sid)
	if !ok {
		r.Logger.WithField("sid", sid).Warn("Session not found")
		http.Error(w, "no session found", http.StatusGone)
		return
	}

	c, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		r.Logger.WithError(err).WithField("sid", sid).Warn("Failed to upgrade session")
		http.Error(w, "Couldn't upgrade connection", http.StatusBadRequest)
		return
	}
	defer c.Close()

	ack, _ := strconv.Atoi(req.URL.Query().Get("ack"))
	pos, _ := strconv.Atoi(req.URL.Query().Get("pos"))

	sess.Serve(c, ack, pos)
}

func (r *Relay) getSession(sid string) (s *session, ok bool) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	s, ok = r.sessions[sid]
	return
}

func (r *Relay) setSession(sid string, s *session) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	if r.sessions == nil {
		r.sessions = map[string]*session{}
	}
	r.sessions[sid] = s
}

func (r *Relay) deleteSession(sid string) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	delete(r.sessions, sid)
}
