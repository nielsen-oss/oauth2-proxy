package validation

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/mbland/hmacauth"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
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

	providerMsgs, err := validateProviders(o)
	if err != nil {
		return err
	}
	msgs = append(msgs, providerMsgs...)

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
