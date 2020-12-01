package options

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/spf13/pflag"
)

type LegacyOptions struct {
	// Legacy options related to upstream servers
	LegacyUpstreams LegacyUpstreams `cfg:",squash"`

	LegacyProvider LegacyProvider `cfg:",squash"`

	Options Options `cfg:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyUpstreams: LegacyUpstreams{
			PassHostHeader:  true,
			ProxyWebSockets: true,
			FlushInterval:   time.Duration(1) * time.Second,
		},
		LegacyProvider: LegacyProvider{},
		Options:        *NewOptions(),
	}
}

func NewLegacyFlagSet() *pflag.FlagSet {
	flagSet := NewFlagSet()

	flagSet.AddFlagSet(legacyProviderFlagSet())

	return flagSet
}

func (l *LegacyOptions) ToOptions() (*Options, error) {
	upstreams, err := l.LegacyUpstreams.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting upstreams: %v", err)
	}
	l.Options.UpstreamServers = upstreams

	providers, err := l.LegacyProvider.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting provider: %v", err)
	}
	l.Options.Providers = providers

	return &l.Options, nil
}

type LegacyUpstreams struct {
	FlushInterval                 time.Duration `flag:"flush-interval" cfg:"flush_interval"`
	PassHostHeader                bool          `flag:"pass-host-header" cfg:"pass_host_header"`
	ProxyWebSockets               bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	SSLUpstreamInsecureSkipVerify bool          `flag:"ssl-upstream-insecure-skip-verify" cfg:"ssl_upstream_insecure_skip_verify"`
	Upstreams                     []string      `flag:"upstream" cfg:"upstreams"`
}

type LegacyProvider struct {
	ClientID         string `flag:"client-id" cfg:"client_id"`
	ClientSecret     string `flag:"client-secret" cfg:"client_secret"`
	ClientSecretFile string `flag:"client-secret-file" cfg:"client_secret_file"`

	KeycloakGroup            string   `flag:"keycloak-group" cfg:"keycloak_group"`
	AzureTenant              string   `flag:"azure-tenant" cfg:"azure_tenant"`
	BitbucketTeam            string   `flag:"bitbucket-team" cfg:"bitbucket_team"`
	BitbucketRepository      string   `flag:"bitbucket-repository" cfg:"bitbucket_repository"`
	GitHubOrg                string   `flag:"github-org" cfg:"github_org"`
	GitHubTeam               string   `flag:"github-team" cfg:"github_team"`
	GitHubRepo               string   `flag:"github-repo" cfg:"github_repo"`
	GitHubToken              string   `flag:"github-token" cfg:"github_token"`
	GitHubUsers              []string `flag:"github-user" cfg:"github_users"`
	GitLabGroup              []string `flag:"gitlab-group" cfg:"gitlab_groups"`
	GoogleGroups             []string `flag:"google-group" cfg:"google_group"`
	GoogleAdminEmail         string   `flag:"google-admin-email" cfg:"google_admin_email"`
	GoogleServiceAccountJSON string   `flag:"google-service-account-json" cfg:"google_service_account_json"`

	ProviderType    string   `flag:"provider" cfg:"provider"`
	ProviderName    string   `flag:"provider-display-name" cfg:"provider_display_name"`
	ProviderCAFiles []string `flag:"provider-ca-file" cfg:"provider_ca_files"`

	OIDCIssuerURL                      string `flag:"oidc-issuer-url" cfg:"oidc_issuer_url"`
	InsecureOIDCAllowUnverifiedEmail   bool   `flag:"insecure-oidc-allow-unverified-email" cfg:"insecure_oidc_allow_unverified_email"`
	InsecureOIDCSkipIssuerVerification bool   `flag:"insecure-oidc-skip-issuer-verification" cfg:"insecure_oidc_skip_issuer_verification"`
	SkipOIDCDiscovery                  bool   `flag:"skip-oidc-discovery" cfg:"skip_oidc_discovery"`
	OIDCJwksURL                        string `flag:"oidc-jwks-url" cfg:"oidc_jwks_url"`

	LoginURL          string `flag:"login-url" cfg:"login_url"`
	RedeemURL         string `flag:"redeem-url" cfg:"redeem_url"`
	ProfileURL        string `flag:"profile-url" cfg:"profile_url"`
	ProtectedResource string `flag:"resource" cfg:"resource"`
	ValidateURL       string `flag:"validate-url" cfg:"validate_url"`
	Scope             string `flag:"scope" cfg:"scope"`
	Prompt            string `flag:"prompt" cfg:"prompt"`
	ApprovalPrompt    string `flag:"approval-prompt" cfg:"approval_prompt"` // Deprecated by OIDC 1.0
	UserIDClaim       string `flag:"user-id-claim" cfg:"user_id_claim"`

	AcrValues  string `flag:"acr-values" cfg:"acr_values"`
	JWTKey     string `flag:"jwt-key" cfg:"jwt_key"`
	JWTKeyFile string `flag:"jwt-key-file" cfg:"jwt_key_file"`
	PubJWKURL  string `flag:"pubjwk-url" cfg:"pubjwk_url"`
}

func legacyUpstreamsFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("upstreams", pflag.ExitOnError)

	flagSet.Duration("flush-interval", time.Duration(1)*time.Second, "period between response flushing when streaming responses")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Bool("proxy-websockets", true, "enables WebSocket proxying")
	flagSet.Bool("ssl-upstream-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS upstreams")
	flagSet.StringSlice("upstream", []string{}, "the http url(s) of the upstream endpoint, file:// paths for static files or static://<status_code> for static response. Routing is based on the path")

	return flagSet
}

func legacyProviderFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("providers", pflag.ExitOnError)

	flagSet.String("client-id", "", "the OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
	flagSet.String("client-secret-file", "", "the file with OAuth Client Secret")

	flagSet.String("keycloak-group", "", "restrict login to members of this group.")
	flagSet.String("azure-tenant", "common", "go to a tenant-specific or common (tenant-independent) endpoint.")
	flagSet.String("bitbucket-team", "", "restrict logins to members of this team")
	flagSet.String("bitbucket-repository", "", "restrict logins to user with access to this repository")
	flagSet.String("github-org", "", "restrict logins to members of this organisation")
	flagSet.String("github-team", "", "restrict logins to members of this team")
	flagSet.String("github-repo", "", "restrict logins to collaborators of this repository")
	flagSet.String("github-token", "", "the token to use when verifying repository collaborators (must have push access to the repository)")
	flagSet.StringSlice("github-user", []string{}, "allow users with these usernames to login even if they do not belong to the specified org and team or collaborators (may be given multiple times)")
	flagSet.StringSlice("gitlab-group", []string{}, "restrict logins to members of this group (may be given multiple times)")
	flagSet.StringSlice("google-group", []string{}, "restrict logins to members of this google group (may be given multiple times).")
	flagSet.String("google-admin-email", "", "the google admin to impersonate for api calls")
	flagSet.String("google-service-account-json", "", "the path to the service account json credentials")

	//TODO (yanasega): verify google can be skipped as defualt provider
	flagSet.String("provider", "", "OAuth provider")
	flagSet.String("provider-display-name", "", "Provider display name")
	flagSet.StringSlice("provider-ca-file", []string{}, "One or more paths to CA certificates that should be used when connecting to the provider.  If not specified, the default Go trust sources are used instead.")
	flagSet.String("oidc-issuer-url", "", "OpenID Connect issuer URL (ie: https://accounts.google.com)")
	flagSet.Bool("insecure-oidc-allow-unverified-email", false, "Don't fail if an email address in an id_token is not verified")
	flagSet.Bool("insecure-oidc-skip-issuer-verification", false, "Do not verify if issuer matches OIDC discovery URL")
	flagSet.Bool("skip-oidc-discovery", false, "Skip OIDC discovery and use manually supplied Endpoints")
	flagSet.String("oidc-jwks-url", "", "OpenID Connect JWKS URL (ie: https://www.googleapis.com/oauth2/v3/certs)")
	flagSet.String("login-url", "", "Authentication endpoint")
	flagSet.String("redeem-url", "", "Token redemption endpoint")
	flagSet.String("profile-url", "", "Profile access endpoint")
	flagSet.String("resource", "", "The resource that is protected (Azure AD only)")
	flagSet.String("validate-url", "", "Access token validation endpoint")
	flagSet.String("scope", "", "OAuth scope specification")
	flagSet.String("prompt", "", "OIDC prompt")
	flagSet.String("approval-prompt", "force", "OAuth approval_prompt")
	flagSet.String("user-id-claim", "email", "which claim contains the user ID")

	flagSet.String("acr-values", "", "acr values string:  optional")
	flagSet.String("jwt-key", "", "private key in PEM format used to sign JWT, so that you can say something like -jwt-key=\"${OAUTH2_PROXY_JWT_KEY}\": required by login.gov")
	flagSet.String("jwt-key-file", "", "path to the private key file in PEM format used to sign the JWT so that you can say something like -jwt-key-file=/etc/ssl/private/jwt_signing_key.pem: required by login.gov")
	flagSet.String("pubjwk-url", "", "JWK pubkey access endpoint: required by login.gov")

	return flagSet
}

func (l *LegacyUpstreams) convert() (Upstreams, error) {
	upstreams := Upstreams{}

	for _, upstreamString := range l.Upstreams {
		u, err := url.Parse(upstreamString)
		if err != nil {
			return nil, fmt.Errorf("could not parse upstream %q: %v", upstreamString, err)
		}

		if u.Path == "" {
			u.Path = "/"
		}

		upstream := Upstream{
			ID:                    u.Path,
			Path:                  u.Path,
			URI:                   upstreamString,
			InsecureSkipTLSVerify: l.SSLUpstreamInsecureSkipVerify,
			PassHostHeader:        &l.PassHostHeader,
			ProxyWebSockets:       &l.ProxyWebSockets,
			FlushInterval:         &l.FlushInterval,
		}

		switch u.Scheme {
		case "file":
			if u.Fragment != "" {
				upstream.ID = u.Fragment
				upstream.Path = u.Fragment
				// Trim the fragment from the end of the URI
				upstream.URI = strings.SplitN(upstreamString, "#", 2)[0]
			}
		case "static":
			responseCode, err := strconv.Atoi(u.Host)
			if err != nil {
				logger.Errorf("unable to convert %q to int, use default \"200\"", u.Host)
				responseCode = 200
			}
			upstream.Static = true
			upstream.StaticCode = &responseCode

			// This is not allowed to be empty and must be unique
			upstream.ID = upstreamString

			// We only support the root path in the legacy config
			upstream.Path = "/"

			// Force defaults compatible with static responses
			upstream.URI = ""
			upstream.InsecureSkipTLSVerify = false
			upstream.PassHostHeader = nil
			upstream.ProxyWebSockets = nil
			upstream.FlushInterval = nil
		}

		upstreams = append(upstreams, upstream)
	}

	return upstreams, nil
}

func (l *LegacyProvider) convert() (Providers, error) {
	providers := Providers{}

	provider := Provider{
		ClientID:          l.ClientID,
		ClientSecret:      l.ClientSecret,
		ClientSecretFile:  l.ClientSecretFile,
		ProviderType:      l.ProviderType,
		ProviderCAFiles:   l.ProviderCAFiles,
		LoginURL:          l.LoginURL,
		RedeemURL:         l.RedeemURL,
		ProfileURL:        l.ProfileURL,
		ProtectedResource: l.ProtectedResource,
		ValidateURL:       l.ValidateURL,
		Scope:             l.Scope,
		Prompt:            l.Prompt,
		ApprovalPrompt:    l.ApprovalPrompt,
		AcrValues:         l.AcrValues,
	}

	switch provider.ProviderType {
	case "github":
		provider.GitHubConfig = GitHubOptions{
			GitHubOrg:   l.GitHubOrg,
			GitHubTeam:  l.GitHubTeam,
			GitHubRepo:  l.GitHubRepo,
			GitHubToken: l.GitHubToken,
			GitHubUsers: l.GitHubUsers,
		}
	case "keycloak":
		provider.KeycloakConfig = KeycloakOptions{
			KeycloakGroup: l.KeycloakGroup,
		}
	case "azure":
		provider.AzureConfig = AzureOptions{
			AzureTenant: l.AzureTenant,
		}
	case "gitlab":
		provider.GitLabConfig = GitLabOptions{
			GitLabGroup: l.GitLabGroup,
		}
		provider.OIDCConfig = OIDCOptions{
			OIDCIssuerURL:                      l.OIDCIssuerURL,
			InsecureOIDCAllowUnverifiedEmail:   l.InsecureOIDCAllowUnverifiedEmail,
			InsecureOIDCSkipIssuerVerification: l.InsecureOIDCSkipIssuerVerification,
			SkipOIDCDiscovery:                  l.SkipOIDCDiscovery,
			OIDCJwksURL:                        l.OIDCJwksURL,
			UserIDClaim:                        l.UserIDClaim,
		}
	case "oidc":
		provider.OIDCConfig = OIDCOptions{
			OIDCIssuerURL:                      l.OIDCIssuerURL,
			InsecureOIDCAllowUnverifiedEmail:   l.InsecureOIDCAllowUnverifiedEmail,
			InsecureOIDCSkipIssuerVerification: l.InsecureOIDCSkipIssuerVerification,
			SkipOIDCDiscovery:                  l.SkipOIDCDiscovery,
			OIDCJwksURL:                        l.OIDCJwksURL,
			UserIDClaim:                        l.UserIDClaim,
		}
	case "login.gov":
		provider.LoginGovConfig = LoginGovOptions{
			JWTKey:     l.JWTKey,
			JWTKeyFile: l.JWTKeyFile,
			PubJWKURL:  l.PubJWKURL,
		}
	case "bitbucket":
		provider.BitbucketConfig = BitbucketOptions{
			BitbucketTeam:       l.BitbucketTeam,
			BitbucketRepository: l.BitbucketRepository,
		}
	case "google":
		provider.GoogleConfig = GoogleOptions{
			GoogleGroups:             l.GoogleGroups,
			GoogleAdminEmail:         l.GoogleAdminEmail,
			GoogleServiceAccountJSON: l.GoogleServiceAccountJSON,
		}
	}

	if l.ProviderName != "" {
		provider.ProviderID = l.ProviderName
		provider.ProviderName = l.ProviderName
	} else {
		// TODO (yanasega): should set a better defualt id value
		provider.ProviderID = l.ProviderType + "_" + l.ClientID
	}

	providers = append(providers, provider)

	return providers, nil
}
