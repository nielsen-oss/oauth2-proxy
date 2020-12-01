package validation

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/mbland/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/providers"
)

// Validate checks that required options are set and validates those that they
// are of the correct format
func Validate(o *options.Options) error {
	msgs := validateCookie(o.Cookie)
	msgs = append(msgs, validateSessionCookieMinimal(o)...)

	if o.SSLInsecureSkipVerify {
		// InsecureSkipVerify is a configurable option we allow
		/* #nosec G402 */
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	}

	// TODO (yanasega): can be skipped in our spesific use case to lighten the multiple providers flow
	// else if len(o.ProviderCAFiles) > 0 {
	// 	pool, err := util.GetCertPool(o.ProviderCAFiles)
	// 	if err == nil {
	// 		transport := &http.Transport{
	// 			TLSClientConfig: &tls.Config{
	// 				RootCAs: pool,
	// 			},
	// 		}

	// 		http.DefaultClient = &http.Client{Transport: transport}
	// 	} else {
	// 		msgs = append(msgs, fmt.Sprintf("unable to load provider CA file(s): %v", err))
	// 	}
	// }

	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	if o.SetBasicAuth && o.SetAuthorization {
		msgs = append(msgs, "mutually exclusive: set-basic-auth and set-authorization-header can not both be true")
	}

	if o.PreferEmailToUser && !o.PassBasicAuth && !o.PassUserHeaders {
		msgs = append(msgs, "PreferEmailToUser should only be used with PassBasicAuth or PassUserHeaders")
	}

	if o.SkipProviderButton && len(o.Providers) > 1 {
		msgs = append(msgs, "SkipProviderButton and multiple providers are mutually exclusive")
	}

	providerIDs := make(map[string]string)
	for _, provider := range o.Providers {

		if provider.ProviderID == "" {
			msgs = append(msgs, "provider has empty id: ids are required for all providers")
		}

		// Ensure provider IDs are unique
		if _, ok := providerIDs[provider.ProviderID]; ok {
			msgs = append(msgs, fmt.Sprintf("multiple providers found with id %q: provider ids must be unique", provider.ProviderID))
		}

		if provider.ClientID == "" {
			msgs = append(msgs, "provider %s missing setting: client-id", provider.ProviderID)
		}

		// login.gov uses a signed JWT to authenticate, not a client-secret
		if provider.ProviderType != "login.gov" {
			if provider.ClientSecret == "" && provider.ClientSecretFile == "" {
				msgs = append(msgs, "provider %s missing setting: client-secret or client-secret-file", provider.ProviderID)
			}
			if provider.ClientSecret == "" && provider.ClientSecretFile != "" {
				_, err := ioutil.ReadFile(provider.ClientSecretFile)
				if err != nil {
					msgs = append(msgs, "provider %s could not read client secret file: %s", provider.ProviderID, provider.ClientSecretFile)
				}
			}
		}

		if provider.OIDCConfig.OIDCIssuerURL != "" {

			ctx := context.Background()

			if provider.OIDCConfig.InsecureOIDCSkipIssuerVerification && !provider.OIDCConfig.SkipOIDCDiscovery {
				// go-oidc doesn't let us pass bypass the issuer check this in the oidc.NewProvider call
				// (which uses discovery to get the URLs), so we'll do a quick check ourselves and if
				// we get the URLs, we'll just use the non-discovery path.

				logger.Printf("Performing OIDC Discovery for provider: %s...", provider.ProviderID)

				requestURL := strings.TrimSuffix(provider.OIDCConfig.OIDCIssuerURL, "/") + "/.well-known/openid-configuration"
				body, err := requests.New(requestURL).
					WithContext(ctx).
					Do().
					UnmarshalJSON()
				if err != nil {
					logger.Errorf("error: failed to discover %s OIDC provider configuration: %v", provider.ProviderID, err)
				} else {
					// Prefer manually configured URLs. It's a bit unclear
					// why you'd be doing discovery and also providing the URLs
					// explicitly though...
					if provider.LoginURL == "" {
						provider.LoginURL = body.Get("authorization_endpoint").MustString()
					}

					if provider.RedeemURL == "" {
						provider.RedeemURL = body.Get("token_endpoint").MustString()
					}

					if provider.OIDCConfig.OIDCJwksURL == "" {
						provider.OIDCConfig.OIDCJwksURL = body.Get("jwks_uri").MustString()
					}

					if provider.ProfileURL == "" {
						provider.ProfileURL = body.Get("userinfo_endpoint").MustString()
					}

					provider.OIDCConfig.SkipOIDCDiscovery = true
				}
			}

			// Construct a manual IDTokenVerifier from issuer URL & JWKS URI
			// instead of metadata discovery if we enable -skip-oidc-discovery.
			// In this case we need to make sure the required endpoints for
			// the provider are configured.
			if provider.OIDCConfig.SkipOIDCDiscovery {
				if provider.LoginURL == "" {
					msgs = append(msgs, provider.ProviderID+" provider missing setting: login-url")
				}
				if provider.RedeemURL == "" {
					msgs = append(msgs, provider.ProviderID+" provider missing setting: redeem-url")
				}
				if provider.OIDCConfig.OIDCJwksURL == "" {
					msgs = append(msgs, provider.ProviderID+" provider missing setting: oidc-jwks-url")
				}
				keySet := oidc.NewRemoteKeySet(ctx, provider.OIDCConfig.OIDCJwksURL)
				o.SetOIDCVerifier(provider.ProviderID, oidc.NewVerifier(provider.OIDCConfig.OIDCIssuerURL, keySet, &oidc.Config{
					ClientID:        provider.ClientID,
					SkipIssuerCheck: provider.OIDCConfig.InsecureOIDCSkipIssuerVerification,
				}))
			} else {
				// Configure discoverable provider data.
				oidcProvider, err := oidc.NewProvider(ctx, provider.OIDCConfig.OIDCIssuerURL)
				if err != nil {
					return err
				}
				o.SetOIDCVerifier(provider.ProviderID, oidcProvider.Verifier(&oidc.Config{
					ClientID:        provider.ClientID,
					SkipIssuerCheck: provider.OIDCConfig.InsecureOIDCSkipIssuerVerification,
				}))

				provider.LoginURL = oidcProvider.Endpoint().AuthURL
				provider.RedeemURL = oidcProvider.Endpoint().TokenURL
			}
			if provider.Scope == "" {
				provider.Scope = "openid email profile"
			}
		}

		msgs = parseProviderInfo(o, provider, msgs)

		if len(provider.GoogleConfig.GoogleGroups) > 0 || provider.GoogleConfig.GoogleAdminEmail != "" || provider.GoogleConfig.GoogleServiceAccountJSON != "" {
			if len(provider.GoogleConfig.GoogleGroups) < 1 {
				msgs = append(msgs, provider.ProviderID+" provider missing setting: google-group")
			}
			if provider.GoogleConfig.GoogleAdminEmail == "" {
				msgs = append(msgs, provider.ProviderID+" provider missing setting: google-admin-email")
			}
			if provider.GoogleConfig.GoogleServiceAccountJSON == "" {
				msgs = append(msgs, provider.ProviderID+" provider missing setting: google-service-account-json")
			}
		}
	}

	if o.SkipJwtBearerTokens {
		// Configure extra issuers
		if len(o.ExtraJwtIssuers) > 0 {
			var jwtIssuers []jwtIssuer
			jwtIssuers, msgs = parseJwtIssuers(o.ExtraJwtIssuers, msgs)
			for _, jwtIssuer := range jwtIssuers {
				verifier, err := newVerifierFromJwtIssuer(jwtIssuer)
				if err != nil {
					msgs = append(msgs, fmt.Sprintf("error building verifiers: %s", err))
				}
				o.SetJWTBearerVerifiers(append(o.GetJWTBearerVerifiers(), verifier))
			}
		}
	}

	var redirectURL *url.URL
	redirectURL, msgs = parseURL(o.RawRedirectURL, "redirect", msgs)
	o.SetRedirectURL(redirectURL)

	msgs = append(msgs, validateUpstreams(o.UpstreamServers)...)

	for _, u := range o.SkipAuthRegex {
		compiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error compiling regex=%q %s", u, err))
			continue
		}
		o.SetCompiledRegex(append(o.GetCompiledRegex(), compiledRegex))
	}

	msgs = parseSignatureKey(o, msgs)
	msgs = configureLogger(o.Logging, msgs)

	if o.ReverseProxy {
		parser, err := ip.GetRealClientIPParser(o.RealClientIPHeader)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("real_client_ip_header (%s) not accepted parameter value: %v", o.RealClientIPHeader, err))
		}
		o.SetRealClientIPParser(parser)

		// Allow the logger to get client IPs
		logger.SetGetClientFunc(func(r *http.Request) string {
			return ip.GetClientString(o.GetRealClientIPParser(), r, false)
		})
	}

	if len(o.TrustedIPs) > 0 && o.ReverseProxy {
		_, err := fmt.Fprintln(os.Stderr, "WARNING: trusting of IPs with --reverse-proxy poses risks if a header spoofing attack is possible.")
		if err != nil {
			panic(err)
		}
	}

	for i, ipStr := range o.TrustedIPs {
		if nil == ip.ParseIPNet(ipStr) {
			msgs = append(msgs, fmt.Sprintf("trusted_ips[%d] (%s) could not be recognized", i, ipStr))
		}
	}

	if len(msgs) != 0 {
		return fmt.Errorf("invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseProviderInfo(o *options.Options, po options.Provider, msgs []string) []string {
	p := &providers.ProviderData{
		ProviderID:       po.ProviderID,
		Scope:            po.Scope,
		ClientID:         po.ClientID,
		ClientSecret:     po.ClientSecret,
		ClientSecretFile: po.ClientSecretFile,
		Prompt:           po.Prompt,
		ApprovalPrompt:   po.ApprovalPrompt,
		AcrValues:        po.AcrValues,
	}
	p.LoginURL, msgs = parseURL(po.LoginURL, "login", msgs)
	p.RedeemURL, msgs = parseURL(po.RedeemURL, "redeem", msgs)
	p.ProfileURL, msgs = parseURL(po.ProfileURL, "profile", msgs)
	p.ValidateURL, msgs = parseURL(po.ValidateURL, "validate", msgs)
	p.ProtectedResource, msgs = parseURL(po.ProtectedResource, "resource", msgs)

	o.SetProvider(po.ProviderID, providers.New(po.ProviderType, p))
	switch p := o.GetProviders()[po.ProviderID].(type) {
	case *providers.AzureProvider:
		p.Configure(po.AzureConfig.AzureTenant)
	case *providers.GitHubProvider:
		p.SetOrgTeam(po.GitHubConfig.GitHubOrg, po.GitHubConfig.GitHubTeam)
		p.SetRepo(po.GitHubConfig.GitHubRepo, po.GitHubConfig.GitHubToken)
		p.SetUsers(po.GitHubConfig.GitHubUsers)
	case *providers.KeycloakProvider:
		p.SetGroup(po.KeycloakConfig.KeycloakGroup)
	case *providers.GoogleProvider:
		if po.GoogleConfig.GoogleServiceAccountJSON != "" {
			file, err := os.Open(po.GoogleConfig.GoogleServiceAccountJSON)
			if err != nil {
				msgs = append(msgs, "invalid Google credentials file: "+po.GoogleConfig.GoogleServiceAccountJSON)
			} else {
				p.SetGroupRestriction(po.GoogleConfig.GoogleGroups, po.GoogleConfig.GoogleAdminEmail, file)
			}
		}
	case *providers.BitbucketProvider:
		p.SetTeam(po.BitbucketConfig.BitbucketTeam)
		p.SetRepository(po.BitbucketConfig.BitbucketRepository)
	case *providers.OIDCProvider:
		p.AllowUnverifiedEmail = po.OIDCConfig.InsecureOIDCAllowUnverifiedEmail
		p.UserIDClaim = po.OIDCConfig.UserIDClaim
		if o.GetOIDCVerifiers()[po.ProviderID] == nil {
			msgs = append(msgs, "oidc provider requires an oidc issuer URL")
		} else {
			p.Verifier = o.GetOIDCVerifiers()[po.ProviderID]
		}
	case *providers.GitLabProvider:
		p.AllowUnverifiedEmail = po.OIDCConfig.InsecureOIDCAllowUnverifiedEmail
		p.Groups = po.GitLabConfig.GitLabGroup
		p.EmailDomains = o.EmailDomains

		if o.GetOIDCVerifiers()[po.ProviderID] != nil {
			p.Verifier = o.GetOIDCVerifiers()[po.ProviderID]
		} else {
			// Initialize with default verifier for gitlab.com
			ctx := context.Background()

			provider, err := oidc.NewProvider(ctx, "https://gitlab.com")
			if err != nil {
				msgs = append(msgs, po.ProviderID+" provider failed to initialize oidc provider for gitlab.com")
			} else {
				p.Verifier = provider.Verifier(&oidc.Config{
					ClientID: po.ClientID,
				})

				p.LoginURL, msgs = parseURL(provider.Endpoint().AuthURL, "login", msgs)
				p.RedeemURL, msgs = parseURL(provider.Endpoint().TokenURL, "redeem", msgs)
			}
		}
	case *providers.LoginGovProvider:
		p.PubJWKURL, msgs = parseURL(po.LoginGovConfig.PubJWKURL, "pubjwk", msgs)

		// JWT key can be supplied via env variable or file in the filesystem, but not both.
		switch {
		case po.LoginGovConfig.JWTKey != "" && po.LoginGovConfig.JWTKeyFile != "":
			msgs = append(msgs, "cannot set both jwt-key and jwt-key-file options for provider: "+po.ProviderID)
		case po.LoginGovConfig.JWTKey == "" && po.LoginGovConfig.JWTKeyFile == "":
			msgs = append(msgs, "login.gov provider requires a private key for signing JWTs for provider: "+po.ProviderID)
		case po.LoginGovConfig.JWTKey != "":
			// The JWT Key is in the commandline argument
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(po.LoginGovConfig.JWTKey))
			if err != nil {
				msgs = append(msgs, "could not parse RSA Private Key PEM for provider: "+po.ProviderID)
			} else {
				p.JWTKey = signKey
			}
		case po.LoginGovConfig.JWTKeyFile != "":
			// The JWT key is in the filesystem
			keyData, err := ioutil.ReadFile(po.LoginGovConfig.JWTKeyFile)
			if err != nil {
				msgs = append(msgs, "could not read key file: "+po.LoginGovConfig.JWTKeyFile+" for provider: "+po.ProviderID)
			}
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
			if err != nil {
				msgs = append(msgs, "could not parse private key from PEM file:"+po.LoginGovConfig.JWTKeyFile+" for provider: "+po.ProviderID)
			} else {
				p.JWTKey = signKey
			}
		}
	}
	return msgs
}

func parseSignatureKey(o *options.Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	var hash crypto.Hash
	var err error
	if hash, err = hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+
			o.SignatureKey)
	}
	o.SetSignatureData(&options.SignatureData{Hash: hash, Key: secretKey})
	return msgs
}

// parseJwtIssuers takes in an array of strings in the form of issuer=audience
// and parses to an array of jwtIssuer structs.
func parseJwtIssuers(issuers []string, msgs []string) ([]jwtIssuer, []string) {
	parsedIssuers := make([]jwtIssuer, 0, len(issuers))
	for _, jwtVerifier := range issuers {
		components := strings.Split(jwtVerifier, "=")
		if len(components) < 2 {
			msgs = append(msgs, fmt.Sprintf("invalid jwt verifier uri=audience spec: %s", jwtVerifier))
			continue
		}
		uri, audience := components[0], strings.Join(components[1:], "=")
		parsedIssuers = append(parsedIssuers, jwtIssuer{issuerURI: uri, audience: audience})
	}
	return parsedIssuers, msgs
}

// newVerifierFromJwtIssuer takes in issuer information in jwtIssuer info and returns
// a verifier for that issuer.
func newVerifierFromJwtIssuer(jwtIssuer jwtIssuer) (*oidc.IDTokenVerifier, error) {
	config := &oidc.Config{
		ClientID: jwtIssuer.audience,
	}
	// Try as an OpenID Connect Provider first
	var verifier *oidc.IDTokenVerifier
	provider, err := oidc.NewProvider(context.Background(), jwtIssuer.issuerURI)
	if err != nil {
		// Try as JWKS URI
		jwksURI := strings.TrimSuffix(jwtIssuer.issuerURI, "/") + "/.well-known/jwks.json"
		if err := requests.New(jwksURI).Do().Error(); err != nil {
			return nil, err
		}

		verifier = oidc.NewVerifier(jwtIssuer.issuerURI, oidc.NewRemoteKeySet(context.Background(), jwksURI), config)
	} else {
		verifier = provider.Verifier(config)
	}
	return verifier, nil
}

// jwtIssuer hold parsed JWT issuer info that's used to construct a verifier.
type jwtIssuer struct {
	issuerURI string
	audience  string
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}
