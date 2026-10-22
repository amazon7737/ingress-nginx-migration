package e2e

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

const (
	serverAliasAuthHost          = "server-alias-auth"
	serverAliasAuthAlias         = "server-alias-auth-alt"
	serverAliasAuthIngressName   = "server-alias-auth-exact"
	serverAliasPublicIngressName = "server-alias-auth-public"
	serverAliasAuthSecretName    = "server-alias-auth" // #nosec G101 -- Kubernetes Secret resource name, not a credential.
	serverAliasAuthPath          = "/admin/report"
	serverAliasAuthUser          = "aliasuser"
	serverAliasAuthPass          = "aliaspass"
	serverAliasAuthRealm         = "Server alias"
)

// ServerAliasAuthSuite checks that a server-alias declared by one Ingress also
// serves the paths of the other Ingresses of the host, so an alias cannot be
// used to reach a protected path through another Ingress's location.
type ServerAliasAuthSuite struct {
	BaseSuite
}

func TestServerAliasAuthSuite(t *testing.T) { //nolint:paralleltest // Suites share cluster resources and must run sequentially.
	suite.Run(t, new(ServerAliasAuthSuite))
}

func (s *ServerAliasAuthSuite) SetupSuite() {
	s.BaseSuite.SetupSuite()

	for _, c := range []*Cluster{s.traefik, s.nginx} {
		err := c.DeploySecret(secretTemplateData{
			Name: serverAliasAuthSecretName,
			Data: map[string]string{
				"auth": base64.StdEncoding.EncodeToString([]byte(htpasswdSHA(serverAliasAuthUser, serverAliasAuthPass))),
			},
		})
		s.Require().NoError(err, "deploy auth secret to %s cluster", c.Name)

		host := serverAliasAuthHost + "." + c.Name + ".local"
		alias := serverAliasAuthAlias + "." + c.Name + ".local"

		err = c.DeployIngressWith(ingressTemplateData{
			Name:     serverAliasAuthIngressName,
			Host:     host,
			Path:     serverAliasAuthPath,
			PathType: "Exact",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/auth-type":   "basic",
				"nginx.ingress.kubernetes.io/auth-secret": serverAliasAuthSecretName,
				"nginx.ingress.kubernetes.io/auth-realm":  serverAliasAuthRealm,
			},
		})
		s.Require().NoError(err, "deploy Exact ingress to %s cluster", c.Name)

		err = c.DeployIngressWith(ingressTemplateData{
			Name:     serverAliasPublicIngressName,
			Host:     host,
			Path:     "/",
			PathType: "Prefix",
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/server-alias": alias,
			},
		})
		s.Require().NoError(err, "deploy aliased Prefix ingress to %s cluster", c.Name)

		// The alias only exists through the Prefix ingress; wait for it before testing the Exact path.
		s.Require().Eventually(func() bool {
			resp := c.MakeRequest(s.T(), alias, http.MethodGet, "/other", nil, 1, time.Second)
			return resp != nil && resp.StatusCode == http.StatusOK && backendReached(resp)
		}, 30*time.Second, time.Second, "[%s] server-alias did not become ready", c.Name)
	}
}

func (s *ServerAliasAuthSuite) TearDownSuite() {
	for _, c := range []*Cluster{s.traefik, s.nginx} {
		if c == nil {
			continue
		}
		if s.T().Failed() {
			s.T().Log(c.GetIngressControllerLogs(500))
		}
		_ = c.DeleteIngress(serverAliasAuthIngressName)
		_ = c.DeleteIngress(serverAliasPublicIngressName)
		_ = c.DeleteSecret(serverAliasAuthSecretName)
	}
}

func (s *ServerAliasAuthSuite) TestNoCredentials() {
	s.assertResponse(serverAliasAuthPath, nil, http.StatusUnauthorized)
}

func (s *ServerAliasAuthSuite) TestWrongCredentials() {
	s.assertResponse(serverAliasAuthPath, basicAuthHeader(serverAliasAuthUser, "wrong"), http.StatusUnauthorized)
}

func (s *ServerAliasAuthSuite) TestCorrectCredentials() {
	s.assertResponse(serverAliasAuthPath, basicAuthHeader(serverAliasAuthUser, serverAliasAuthPass), http.StatusOK)
}

func (s *ServerAliasAuthSuite) TestOtherPathsRemainPublic() {
	for _, path := range []string{"/", "/admin", serverAliasAuthPath + "/child"} {
		s.Run(path, func() {
			s.assertResponse(path, nil, http.StatusOK)
		})
	}
}

// assertResponse checks the path on both the host and the alias, which must behave the same.
func (s *ServerAliasAuthSuite) assertResponse(path string, headers map[string]string, status int) {
	s.T().Helper()

	for _, name := range []string{serverAliasAuthHost, serverAliasAuthAlias} {
		s.Run(name, func() {
			for _, scheme := range []string{"http", "https"} {
				s.Run(scheme, func() {
					for _, c := range []*Cluster{s.nginx, s.traefik} {
						s.Run(c.Name, func() {
							host := name + "." + c.Name + ".local"
							var resp *Response
							if scheme == "https" {
								resp = c.MakeTLSRequest(s.T(), host, http.MethodGet, path, headers, nil, 3, time.Second)
							} else {
								resp = c.MakeRequest(s.T(), host, http.MethodGet, path, headers, 3, time.Second)
							}
							s.Require().NotNil(resp, "request to %s%s returned no response", host, path)
							s.Equal(status, resp.StatusCode, "unexpected status for %s%s", host, path)
							if status == http.StatusUnauthorized {
								s.Equal(`Basic realm="`+serverAliasAuthRealm+`"`, resp.ResponseHeaders.Get("WWW-Authenticate"))
								s.False(backendReached(resp), "protected backend served without valid credentials")
							} else {
								s.True(backendReached(resp), "request did not reach the backend")
							}
						})
					}
				})
			}
		})
	}
}
