package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

// StratioProvider represents a Stratio based Identity Provider
type StratioProvider struct {
	*ProviderData
	// SISHost string
	// Tenant string
}

var _ Provider = (*StratioProvider)(nil)

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *StratioProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   int64  `json:"expires"`
	}

	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		expires := time.Now().Add(time.Duration(jsonResponse.ExpiresOn) * time.Second).Truncate(time.Second)
		s = &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
			ExpiresOn:   &expires,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(result.Body()))
	if err != nil {
		return
	}

	var expires time.Time

	if e := v.Get("expires"); e != "" {
		var i int
		i, err = strconv.Atoi(e)
		if err != nil {
			return
		}
		expires = time.Now().Add(time.Duration(i) * time.Second).Truncate(time.Second)
	} else {
		err = fmt.Errorf("no expiration found %s", result.Body())
	}

	if a := v.Get("access_token"); a != "" {
		created := time.Now()
		s = &sessions.SessionState{AccessToken: a, CreatedAt: &created, ExpiresOn: &expires}
	} else {
		err = fmt.Errorf("no access token found %s", result.Body())
	}
	return
}

// NewStratioProvider initiates a new StratioProvider
func NewStratioProvider(p *ProviderData) *StratioProvider {
	p.ProviderName = "Stratio"
	host := os.Getenv("SIS_HOST")
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: host,
			Path: "/sso/oauth2.0/authorize",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: host,
			Path: "/sso/oauth2.0/accessToken",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: host,
			Path: "/sso/oauth2.0/profile",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "read"
	}
	return &StratioProvider{ProviderData: p}
}

func getStratioHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

type stratioUserInfo struct {
	ID     string
	UID    string
	Email  string
	Tenant string
	CN     string
	// Roles  []string
	// Groups []string
}

func (p *StratioProvider) getUserInfo(ctx context.Context, s *sessions.SessionState) (*stratioUserInfo, error) {
	// Retrieve user info JSON
	// Build user info url from profile url of Stratio instance
	var userInfo stratioUserInfo

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(getStratioHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %v", err)
	}

	userInfo.ID, err = json.GetPath("id").String()
	if err != nil {
		return &userInfo, err
	}

	attributes := json.GetPath("attributes")

	for i := range attributes.MustArray() {
		uid, _ := attributes.GetIndex(i).Get("uid").String()
		if uid != "" {
			userInfo.UID = uid
		}

		mail, _ := attributes.GetIndex(i).Get("mail").String()
		if mail != "" {
			userInfo.Email = mail
		}

		tenant, _ := attributes.GetIndex(i).Get("tenant").String()
		if tenant != "" {
			userInfo.Tenant = tenant
			s.Tenant = tenant
		}

		cn, _ := attributes.GetIndex(i).Get("cn").String()
		if cn != "" {
			userInfo.CN = cn
		}

		// userInfo.Roles, _ = attributes.GetIndex(i).Get("mail").MustArray()
		// userInfo.Groups, _ = attributes.GetIndex(i).Get("mail").MustArray()
	}

	return &userInfo, nil
}

// GetEmailAddress returns the Account email address
func (p *StratioProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {

	// Retrieve user info
	userInfo, err := p.getUserInfo(ctx, s)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user info: %v", err)
	}
	return userInfo.Email, nil
}

// GetUserName returns the Account user name
func (p *StratioProvider) GetUserName(ctx context.Context, s *sessions.SessionState) (string, error) {
	// Retrieve user info
	userInfo, err := p.getUserInfo(ctx, s)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user info: %v", err)
	}
	return userInfo.UID, nil
}

// // GetTenant returns the Account Tenant
// func (p *StratioProvider) GetTenant(ctx context.Context, s *sessions.SessionState) (string, error) {
// 	logger.Print("[STG] GetTenant")
// 	if s.AccessToken == "" {
// 		return "", errors.New("missing access token")
// 	}

// 	json, err := requests.New(p.ProfileURL.String()).
// 		WithContext(ctx).
// 		WithHeaders(getStratioHeader(s.AccessToken)).
// 		Do().
// 		UnmarshalJSON()
// 	if err != nil {
// 		return "", err
// 	}

// 	printable, err := json.MarshalJSON()
// 	if err != nil {
// 		return "", err
// 	}
// 	logger.Printf("[STG] JSON profile: %s", string(printable))

// 	attributes := json.GetPath("attributes")

// 	for i := range attributes.MustArray() {
// 		logger.Printf("[STG] GetTenant - tenant: %s\n", attributes.GetIndex(i))

// 		tenant, _ := attributes.GetIndex(i).Get("tenant").String()
// 		if tenant != "" {
// 			return tenant, nil
// 		}
// 	}

// 	return "", nil
// }

// ValidateSessionState validates the AccessToken
func (p *StratioProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	// logger.Print("[STG] ValidateSessionState")
	// logger.Printf("[STG] Access Token: %s", s.AccessToken)
	return validateToken(ctx, p, s.AccessToken, getStratioHeader(s.AccessToken))
}
