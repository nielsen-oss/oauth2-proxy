package validation

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/providers"
)

func validateProviders(o *options.Options) ([]string, error) {
	msgs := []string{}
	providerIDs := make(map[string]string)

	if len(o.Providers) == 0 {
		msgs = append(msgs, "at least one providers has to be defined")
	}

	for _, provider := range o.Providers {

		if provider.ProviderID == "" {
			msgs = append(msgs, "provider has empty id: ids are required for all providers")
		}

		// Ensure provider IDs are unique
		if _, ok := providerIDs[provider.ProviderID]; ok {
			msgs = append(msgs, fmt.Sprintf("multiple providers found with id %s: provider ids must be unique", provider.ProviderID))
		}
		providerIDs[provider.ProviderID] = ""

		if provider.ClientID == "" {
			msgs = append(msgs, fmt.Sprintf("provider %s missing setting: client-id", provider.ProviderID))
		}

		// login.gov uses a signed JWT to authenticate, not a client-secret
		if provider.ProviderType != "login.gov" {
			if provider.ClientSecret == "" && provider.ClientSecretFile == "" {
				msgs = append(msgs, fmt.Sprintf("provider %s missing setting: client-secret or client-secret-file", provider.ProviderID))
			}
			if provider.ClientSecret == "" && provider.ClientSecretFile != "" {
				_, err := ioutil.ReadFile(provider.ClientSecretFile)
				if err != nil {
					msgs = append(msgs, fmt.Sprintf("provider %s could not read client secret file: %s", provider.ProviderID, provider.ClientSecretFile))
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
					return []string{}, err
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
			if provider.OIDCConfig.UserIDClaim == "" {
				provider.OIDCConfig.UserIDClaim = "email"
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
	return msgs, nil
}

func parseProviderInfo(o *options.Options, po options.Provider, msgs []string) []string {
	p := &providers.ProviderData{
		ProviderID:          po.ProviderID,
		ProviderDisplayName: po.ProviderName,
		Scope:               po.Scope,
		ClientID:            po.ClientID,
		ClientSecret:        po.ClientSecret,
		ClientSecretFile:    po.ClientSecretFile,
		Prompt:              po.Prompt,
		ApprovalPrompt:      po.ApprovalPrompt,
		AcrValues:           po.AcrValues,
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
