package server

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/ory/hydra-client-go/client"
	"github.com/ory/hydra-client-go/client/admin"
	"github.com/ory/hydra-client-go/models"
	"github.com/pragkent/hydra-wework/wework"
	"gopkg.in/yaml.v2"
)

const (
	openIDScope      = "openid"
	userAgentKeyword = "wxwork"

	pathLogin    = "/wework/login"
	pathConsent  = "/wework/consent"
	pathAuth     = "/wework/auth"
	pathCallback = "/wework/callback"
)

type Server struct {
	cfg    *Config
	mux    *mux.Router
	hcli   admin.ClientService
	wcli   *wework.Client
	groups map[string][]string
}

func New(c *Config) (*Server, error) {
	adminURL, err := url.Parse(c.HydraURL)
	if err != nil {
		return nil, err
	}

	hydraClient := client.NewHTTPClientWithConfig(nil,
		&client.TransportConfig{
			Schemes:  []string{adminURL.Scheme},
			Host:     adminURL.Host,
			BasePath: adminURL.Path,
		},
	)

	srv := &Server{
		cfg:    c,
		mux:    mux.NewRouter(),
		hcli:   hydraClient.Admin,
		wcli:   wework.NewClient(c.WeworkCorpID, c.WeworkAgentID, c.WeworkSecret),
		groups: make(map[string][]string),
	}
	if err = srv.readConfig(c.GroupConfigPath); err != nil {
		return nil, err
	}

	srv.mux.HandleFunc(pathLogin, srv.LoginHandler)
	srv.mux.HandleFunc(pathConsent, srv.ConsentHandler)
	srv.mux.HandleFunc(pathAuth, srv.AuthHandler)
	srv.mux.HandleFunc(pathCallback, srv.CallbackHandler)

	return srv, nil
}

func (s *Server) readConfig(path string) error {
	bs, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config.yaml: read file error: %v", err)
	}

	err = yaml.Unmarshal(bs, s.groups)
	if err != nil {
		return fmt.Errorf("config.yaml: unmarshal error: %v", err)
	}

	return nil
}

func (s *Server) ListenAndServe() error {
	lis, err := net.Listen("tcp", s.cfg.BindAddr)
	if err != nil {
		return err
	}

	glog.Infof("Listening on %v", lis.Addr())
	return http.Serve(lis, s.mux)
}

func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	loginChallenge := strings.TrimSpace(loginChallengeID(r))
	if loginChallenge == "" {
		glog.Errorf("Login Challenge request id is missing")
		http.Error(w, "Login Challenge request id is missing", http.StatusBadRequest)
		return
	}

	loginGetParam := admin.NewGetLoginRequestParams()
	loginGetParam.WithContext(r.Context())
	loginGetParam.SetLoginChallenge(loginChallenge)

	respLoginGet, err := s.hcli.GetLoginRequest(loginGetParam)
	if err != nil {
		glog.Errorf("Failed When Get Login Request Info : %s", err)
		http.Error(w, "Failed When Get Login Request Info", http.StatusBadRequest)
		return
	}

	payload := respLoginGet.GetPayload()
	if payload.Skip != nil && *payload.Skip {
		// 有登录态, 直接从登录态获取Sub
		s.acceptLoginRequest(w, r, *payload.Subject, loginChallenge)
		return
	}

	// 跳转到企业微信授权
	http.Redirect(w, r, getAuthURL(loginChallenge), http.StatusFound)
}

func (s *Server) ConsentHandler(w http.ResponseWriter, r *http.Request) {
	consentChallenge := strings.TrimSpace(consentID(r))
	if consentChallenge == "" {
		glog.Errorf("Consent Challenge request id is missing")
		http.Error(w, "Consent Challenge request id is missing", http.StatusBadRequest)
		return
	}

	consentGetParams := admin.NewGetConsentRequestParams()
	consentGetParams.WithContext(r.Context())
	consentGetParams.SetConsentChallenge(consentChallenge)

	consentGetResp, err := s.hcli.GetConsentRequest(consentGetParams)
	if err != nil {
		glog.Errorf("Cannot Accept Consent Request : %v", err)
		http.Error(w, "Cannot Accept Consent Request", http.StatusBadRequest)
		return
	}

	// 直接同意, 不做用户确认
	payload := consentGetResp.GetPayload()
	consentAcceptBody := &models.AcceptConsentRequest{
		GrantAccessTokenAudience: payload.RequestedAccessTokenAudience,
		GrantScope:               payload.RequestedScope,
		Session: &models.ConsentRequestSession{
			IDToken: consentGetResp.Payload.Context,
		},
	}

	consentAcceptParams := admin.NewAcceptConsentRequestParams()
	consentAcceptParams.WithContext(r.Context())
	consentAcceptParams.SetConsentChallenge(consentChallenge)
	consentAcceptParams.WithBody(consentAcceptBody)

	consentAcceptResp, err := s.hcli.AcceptConsentRequest(consentAcceptParams)
	if err != nil {
		glog.Errorf("error AcceptConsentRequest : %v", err)
		http.Error(w, "error AcceptConsentRequest", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, *consentAcceptResp.GetPayload().RedirectTo, http.StatusFound)
}

func consentID(r *http.Request) string {
	return r.URL.Query().Get("consent_challenge")
}

func loginChallengeID(r *http.Request) string {
	return r.URL.Query().Get("login_challenge")
}

func getAuthURL(loginChallenge string) string {
	return fmt.Sprintf("%s?login_challenge=%s", pathAuth, loginChallenge)
}

func (s *Server) getTokenVars(uid string) (map[string]interface{}, error) {
	vars := make(map[string]interface{})

	if err := s.collectUserInfo(uid, vars); err != nil {
		return nil, err
	}

	if err := s.collectUserGroups(uid, vars); err != nil {
		return nil, err
	}

	glog.Infof("User authenticated. %v", vars)
	return vars, nil
}

func (s *Server) collectUserInfo(uid string, vars map[string]interface{}) error {
	userResp, err := s.wcli.GetUser(uid)
	if err != nil {
		return fmt.Errorf("get wework user failed. %v", err)
	}

	if userResp.Status != wework.UserActive {
		return errors.New("user is not active")
	}

	vars["username"] = userResp.UserID
	vars["name"] = userResp.EnglishName
	vars["email"] = userResp.Email
	vars["email_verified"] = true

	return nil
}

func (s *Server) collectUserGroups(uid string, vars map[string]interface{}) error {
	if groups, ok := s.groups[uid]; ok {
		vars["groups"] = groups
	} else {
		vars["groups"] = []string{}
	}
	return nil
}

func (s *Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	state := loginChallengeID(r)
	callbackURL := getWeworkCallbackURL(s.cfg.HTTPS, r.Host)

	var u string
	if isInWework(r) {
		u = s.wcli.GetOAuthURL(callbackURL, state)
	} else {
		u = s.wcli.GetQRConnectURL(callbackURL, state)
	}

	http.Redirect(w, r, u, http.StatusFound)
}

func isInWework(r *http.Request) bool {
	return strings.Contains(r.UserAgent(), userAgentKeyword)
}

func getWeworkCallbackURL(https bool, host string) string {
	scheme := "https"
	if !https {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, pathCallback)
}

func (s *Server) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	uid, err := s.wcli.GetUserInfo(code)
	if err != nil {
		glog.Errorf("Get user info failed. %v", err)
		http.Error(w, "Get user info failed", http.StatusInternalServerError)
		return
	}

	glog.Infof("User signed in as wework user %v", uid)
	loginChallenge := r.URL.Query().Get("state")

	// Using Hydra Admin to accept login request!
	loginGetParam := admin.NewGetLoginRequestParams()
	loginGetParam.WithContext(r.Context())
	loginGetParam.SetLoginChallenge(loginChallenge)

	_, err = s.hcli.GetLoginRequest(loginGetParam)
	if err != nil {
		glog.Errorf("error GetLoginRequest: %v", err)
		http.Error(w, "error GetLoginRequest", http.StatusInternalServerError)
		return
	}

	s.acceptLoginRequest(w, r, userToSubject(uid), loginChallenge)
}

func (s *Server) acceptLoginRequest(
	w http.ResponseWriter, r *http.Request, subject, loginChallenge string,
) error {
	extraVars, err := s.getTokenVars(subjectToUserID(subject))
	if err != nil {
		glog.Errorf("Get token extra vars error: %v", err)
		http.Error(w, "Get user profile error", http.StatusInternalServerError)
		return err
	}

	loginAcceptParam := admin.NewAcceptLoginRequestParams()
	loginAcceptParam.WithContext(r.Context())
	loginAcceptParam.SetLoginChallenge(loginChallenge)
	loginAcceptParam.SetBody(&models.AcceptLoginRequest{
		Subject:  &subject,
		Remember: true,
		Context:  extraVars,
	})

	respLoginAccept, err := s.hcli.AcceptLoginRequest(loginAcceptParam)
	if err != nil {
		glog.Errorf("error AcceptLoginRequest: %v", err)
		http.Error(w, "error AcceptLoginRequest", http.StatusInternalServerError)
		return err
	}

	http.Redirect(w, r, *respLoginAccept.GetPayload().RedirectTo, http.StatusFound)
	return nil
}

func userToSubject(uid string) string {
	return fmt.Sprintf("user:%s", uid)
}

func subjectToUserID(sub string) string {
	if strings.HasPrefix(sub, "user:") {
		return sub[len("user:"):]
	} else {
		return ""
	}
}
