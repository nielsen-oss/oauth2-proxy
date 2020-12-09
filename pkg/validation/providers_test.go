package validation

import (
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func NewOptions(providers options.Providers) *options.Options {
	o := options.NewOptions()
	o.Providers = providers
	return o
}

var _ = Describe("Providers", func() {
	type validateProvidersTableInput struct {
		options    *options.Options
		errStrings []string
	}

	validProvider := options.Provider{
		ProviderID:   "ProviderID",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
	}

	validAzureProvider := options.Provider{
		ProviderType: "azure",
		ProviderID:   "ProviderAzure",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		AzureConfig: options.AzureOptions{
			AzureTenant: "test",
		},
	}

	missingIDProvider := options.Provider{
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
	}

	missingProvider := "at least one providers has to be defined"
	emptyIDMsg := "provider has empty id: ids are required for all providers"
	duplicateProviderIDMsg := "multiple providers found with id ProviderID: provider ids must be unique"
	// skipButtonAndMultipleProvidersMsg := "SkipProviderButton and multiple providers are mutually exclusive"

	DescribeTable("validateProviders",
		func(o *validateProvidersTableInput) {
			Expect(validateProviders(o.options)).To(ConsistOf(o.errStrings))
		},
		Entry("with no providers", &validateProvidersTableInput{
			options:    &options.Options{},
			errStrings: []string{missingProvider},
		}),
		Entry("with valid providers", &validateProvidersTableInput{
			options:    NewOptions(options.Providers{validProvider, validAzureProvider}),
			errStrings: []string{},
		}),
		Entry("with an empty providerID", &validateProvidersTableInput{
			options:    NewOptions(options.Providers{missingIDProvider}),
			errStrings: []string{emptyIDMsg},
		}),
		Entry("with same providerID", &validateProvidersTableInput{
			options:    NewOptions(options.Providers{validProvider, validProvider}),
			errStrings: []string{duplicateProviderIDMsg},
		}),
	)
})
