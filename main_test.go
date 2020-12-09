package main

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/spf13/pflag"
)

var _ = Describe("Configuration Loading Suite", func() {
	const testLegacyConfig = `
provider="oidc"
oidc_issuer_url="http://dex.localhost:4190/dex"
client_secret="b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK"
client_id="oauth2-proxy"
provider_display_name="dex"
`

	const testAlphaConfig = `
providers:
- provider: oidc
  ProviderID: dex
  providerDisplayName: dex
  clientID: oauth2-proxy
  clientSecret: b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK
  approvalPrompt: force
  azureConfig:
    azureTenant: common
  oidcConfig:
    userIDClaim: email
    oidcIssuerURL: http://dex.localhost:4190/dex
`

	const testCoreConfig = `
http_address="0.0.0.0:4180"
cookie_secret="OQINaROshtE9TcZkNAm-5Zs2Pv3xaWytBmc5W7sPX7w="
email_domains="example.com"
cookie_secure="false"
redirect_url="http://localhost:4180/oauth2/callback"
`

	testExpectedOptions := func() *options.Options {
		opts, err := options.NewLegacyOptions().ToOptions()
		Expect(err).ToNot(HaveOccurred())

		opts.HTTPAddress = "0.0.0.0:4180"
		opts.Cookie.Secret = "OQINaROshtE9TcZkNAm-5Zs2Pv3xaWytBmc5W7sPX7w="
		opts.EmailDomains = []string{"example.com"}
		opts.Cookie.Secure = false
		opts.RawRedirectURL = "http://localhost:4180/oauth2/callback"

		opts.Providers[0].ClientID = "oauth2-proxy"
		opts.Providers[0].ClientSecret = "b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK"
		opts.Providers[0].ProviderID = "dex"
		opts.Providers[0].ProviderType = "oidc"
		opts.Providers[0].ProviderName = "dex"
		opts.Providers[0].ApprovalPrompt = "force"
		opts.Providers[0].OIDCConfig.OIDCIssuerURL = "http://dex.localhost:4190/dex"
		opts.Providers[0].OIDCConfig.UserIDClaim = "email"
		opts.Providers[0].AzureConfig.AzureTenant = "common"

		return opts
	}

	type loadConfigurationTableInput struct {
		configContent      string
		alphaConfigContent string
		args               []string
		extraFlags         func() *pflag.FlagSet
		expectedOptions    func() *options.Options
		expectedErr        error
	}

	DescribeTable("LoadConfiguration",
		func(in loadConfigurationTableInput) {
			var configFileName, alphaConfigFileName string

			defer func() {
				if configFileName != "" {
					Expect(os.Remove(configFileName)).To(Succeed())
				}
				if alphaConfigFileName != "" {
					Expect(os.Remove(alphaConfigFileName)).To(Succeed())
				}
			}()

			if in.configContent != "" {
				By("Writing the config to a temporary file", func() {
					file, err := ioutil.TempFile("", "oauth2-proxy-test-config-XXXX.cfg")
					Expect(err).ToNot(HaveOccurred())
					defer file.Close()

					configFileName = file.Name()

					_, err = file.WriteString(in.configContent)
					Expect(err).ToNot(HaveOccurred())
				})
			}

			if in.alphaConfigContent != "" {
				By("Writing the config to a temporary file", func() {
					file, err := ioutil.TempFile("", "oauth2-proxy-test-alpha-config-XXXX.yaml")
					Expect(err).ToNot(HaveOccurred())
					defer file.Close()

					alphaConfigFileName = file.Name()

					_, err = file.WriteString(in.alphaConfigContent)
					Expect(err).ToNot(HaveOccurred())
				})
			}

			extraFlags := pflag.NewFlagSet("test-flagset", pflag.ExitOnError)
			if in.extraFlags != nil {
				extraFlags = in.extraFlags()
			}

			opts, err := loadConfiguration(configFileName, alphaConfigFileName, extraFlags, in.args)
			if in.expectedErr != nil {
				Expect(err).To(MatchError(in.expectedErr.Error()))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(in.expectedOptions).ToNot(BeNil())
			Expect(opts).To(Equal(in.expectedOptions()))
		},
		Entry("with legacy configuration", loadConfigurationTableInput{
			configContent:   testCoreConfig + testLegacyConfig,
			expectedOptions: testExpectedOptions,
		}),
		Entry("with alpha configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig,
			alphaConfigContent: testAlphaConfig,
			expectedOptions:    testExpectedOptions,
		}),
		Entry("with bad legacy configuration", loadConfigurationTableInput{
			configContent:   testCoreConfig + "unknown_field=\"something\"",
			expectedOptions: func() *options.Options { return nil },
			expectedErr:     errors.New("failed to load config: error unmarshalling config: 1 error(s) decoding:\n\n* '' has invalid keys: unknown_field"),
		}),
		Entry("with bad alpha configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig,
			alphaConfigContent: testAlphaConfig + ":",
			expectedOptions:    func() *options.Options { return nil },
			expectedErr:        errors.New("failed to load alpha options: error unmarshalling config: error converting YAML to JSON: yaml: line 13: did not find expected key"),
		}),
		Entry("with alpha configuration and bad core configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig + "unknown_field=\"something\"",
			alphaConfigContent: testAlphaConfig,
			expectedOptions:    func() *options.Options { return nil },
			expectedErr:        errors.New("failed to load core options: failed to load config: error unmarshalling config: 1 error(s) decoding:\n\n* '' has invalid keys: unknown_field"),
		}),
	)
})
