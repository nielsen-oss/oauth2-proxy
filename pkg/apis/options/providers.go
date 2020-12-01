package options

// Providers is a collection of definitions for providers.
type Providers []Provider

// Provider holds all provider configuration
type Provider struct {
	ClientID         string `json:"clientID"`
	ClientSecret     string `json:"clientSecret"`
	ClientSecretFile string `json:"clientSecretFile"`

	KeycloakConfig      KeycloakOptions  `json:"keycloakConfig"`
	AzureConfig         AzureOptions     `json:"azureConfig"`
	BitbucketConfig     BitbucketOptions `json:"bitbucketConfig"`
	GitHubConfig        GitHubOptions    `json:"githubConfig"`
	GitLabConfig        GitLabOptions    `json:"gitlabConfig"`
	GoogleConfig        GoogleOptions    `json:"googleConfig"`
	OIDCConfig          OIDCOptions      `json:"oidcConfig"`
	LoginGovConfig      LoginGovOptions  `json:"loginGovConfig"`
	SkipJwtBearerTokens bool             `json:"skipJwtBearerTokens"`
	ExtraJwtIssuers     []string         `json:"extraJwtIssuers"`

	ProviderID      string   `json:"providerID"`
	ProviderType    string   `json:"provider"`
	ProviderName    string   `json:"providerDisplayName"`
	ProviderCAFiles []string `json:"providerCAFiles"`

	LoginURL          string `json:"loginURL"`
	RedeemURL         string `json:"redeemURL"`
	ProfileURL        string `json:"profileURL"`
	ProtectedResource string `json:"resource"`
	ValidateURL       string `json:"validateURL"`
	Scope             string `json:"scope"`
	Prompt            string `json:"prompt"`
	ApprovalPrompt    string `json:"approvalPrompt"`

	AcrValues string `json:"acrValues"`
}

type KeycloakOptions struct {
	KeycloakGroup string `json:"keycloakGroup"`
}

type AzureOptions struct {
	AzureTenant string `json:"azureTenant"`
}

type BitbucketOptions struct {
	BitbucketTeam       string `json:"bitbucketTeam"`
	BitbucketRepository string `json:"bitbucketRepository"`
}

type GitHubOptions struct {
	GitHubOrg   string   `json:"githubOrg"`
	GitHubTeam  string   `json:"githubTeam"`
	GitHubRepo  string   `json:"githubRepo"`
	GitHubToken string   `json:"githubToken"`
	GitHubUsers []string `json:"githubUsers"`
}

type GitLabOptions struct {
	GitLabGroup []string `json:"gitlabGroups"`
}

type GoogleOptions struct {
	GoogleGroups             []string `json:"googleGroup"`
	GoogleAdminEmail         string   `json:"googleAdminEmail"`
	GoogleServiceAccountJSON string   `json:"googleServiceAccountJson"`
}

type OIDCOptions struct {
	OIDCIssuerURL                      string `json:"oidcIssuerURL"`
	InsecureOIDCAllowUnverifiedEmail   bool   `json:"insecureOidcAllowUnverifiedEmail"`
	InsecureOIDCSkipIssuerVerification bool   `json:"insecureOidcSkipIssuerVerification"`
	SkipOIDCDiscovery                  bool   `json:"skipOidcDiscovery"`
	OIDCJwksURL                        string `json:"oidcJwksURL"`
	OIDCGroupsClaim                    string `json:"oidcGroupsClaim"`
	UserIDClaim                        string `json:"userIDClaim"`
}

type LoginGovOptions struct {
	JWTKey     string `json:"jwtKey"`
	JWTKeyFile string `json:"jwtKeyFile"`
	PubJWKURL  string `json:"pubjwkURL"`
}
