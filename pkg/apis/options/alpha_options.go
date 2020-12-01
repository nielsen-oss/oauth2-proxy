package options

// AlphaOptions contains alpha structured configuration options.
// Usage of these options allows users to access alpha features that are not
// available as part of the primary configuration structure for OAuth2 Proxy.
//
// :::warning
// The options within this structure are considered alpha.
// They may change between releases without notice.
// :::
type AlphaOptions struct {
	// Providers is used to configure providers.
	Providers Providers `json:"providers,omitempty"`
}

// MergeInto replaces alpha options in the Options struct with the values
// from the AlphaOptions
func (a *AlphaOptions) MergeInto(opts *Options) {
	opts.Providers = a.Providers
}

// ExtractFrom populates the fields in the AlphaOptions with the values from
// the Options
func (a *AlphaOptions) ExtractFrom(opts *Options) {
	a.Providers = opts.Providers
}
