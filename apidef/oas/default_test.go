package oas

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestOAS_BuildDefaultTykExtension(t *testing.T) {
	t.Parallel()

	t.Run("build tyk extension with no supplied params", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		assert.NoError(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/",
				},
			},
			Upstream: Upstream{
				URL: "https://example-org.com/api",
			},
			Info: Info{
				Name: "OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("build tyk extension with supplied params", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:  "/listen-api",
			UpstreamURL: "https://example.org/api",
		})

		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
			Upstream: Upstream{
				URL: "https://example.org/api",
			},
			Info: Info{
				Name: "OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("do not override existing tyk extension by default", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-path",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-path",
				},
			},
			Upstream: Upstream{
				URL: "https://example-org.com/api",
			},
			Info: Info{
				Name: "New OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("override existing tyk extension with supplied params", func(t *testing.T) {
		const (
			testSSMyAuth = "my_auth"
			testHeader   = "my-header"
		)
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Security: openapi3.SecurityRequirements{
					{testSSMyAuth: []string{}},
				},
				Components: openapi3.Components{
					SecuritySchemes: openapi3.SecuritySchemes{
						testSSMyAuth: &openapi3.SecuritySchemeRef{
							Value: openapi3.NewSecurityScheme().WithType(typeApiKey).WithIn(header).WithName(testHeader),
						},
					},
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:     "/new-listen-api",
			UpstreamURL:    "https://example.org/api",
			Authentication: true,
		})

		assert.Nil(t, err)

		expectedTykExtension := XTykAPIGateway{
			Server: Server{
				ListenPath: ListenPath{
					Value: "/new-listen-api",
				},
				Authentication: &Authentication{
					Enabled: true,
					SecuritySchemes: SecuritySchemes{
						testSSMyAuth: &Token{
							Enabled: true,
							AuthSources: AuthSources{
								Header: &AuthSource{
									Enabled: true,
								},
							},
						},
					},
				},
			},
			Upstream: Upstream{
				URL: "https://example.org/api",
			},
			Info: Info{
				Name: "New OAS API",
				State: State{
					Active: true,
				},
			},
		}

		assert.Equal(t, expectedTykExtension, *oasDef.GetTykExtension())
	})

	t.Run("error when supplied invalid upstreamURL param", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "https://example-org.com/api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{
			ListenPath:  "/new-listen-api",
			UpstreamURL: "invalid-url",
		})
		assert.ErrorIs(t, err, errInvalidUpstreamURL)
	})

	t.Run("error when no supplied params and invalid URL in servers", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
				Servers: openapi3.Servers{
					{
						URL: "/listen-api",
					},
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		assert.ErrorIs(t, err, errInvalidServerURL)
	})

	t.Run("error when no supplied params and no servers", func(t *testing.T) {
		oasDef := OAS{
			T: openapi3.T{
				Info: &openapi3.Info{
					Title: "OAS API",
				},
			},
		}

		existingTykExtension := XTykAPIGateway{
			Info: Info{
				Name: "New OAS API",
			},
			Server: Server{
				ListenPath: ListenPath{
					Value: "/listen-api",
				},
			},
		}

		oasDef.SetTykExtension(&existingTykExtension)

		err := oasDef.BuildDefaultTykExtension(TykExtensionConfigParams{})
		assert.ErrorIs(t, err, errEmptyServersObject)
	})
}

func TestOAS_importAuthentication(t *testing.T) {
	const (
		testSecurityNameToken = "my_auth_token"
		testHeaderName        = "my-auth-token-header"
		testCookieName        = "my-auth-token-cookie"
	)

	t.Run("security is empty", func(t *testing.T) {
		oas := OAS{}
		oas.SetTykExtension(&XTykAPIGateway{})

		err := oas.importAuthentication()
		assert.ErrorIs(t, errEmptySecurityObject, err)

		authentication := oas.getTykAuthentication()
		assert.Nil(t, authentication)
	})

	t.Run("add authentication", func(t *testing.T) {
		oas := OAS{}
		oas.Security = openapi3.SecurityRequirements{
			{testSecurityNameToken: []string{}},
		}

		tokenScheme := openapi3.NewSecurityScheme()
		tokenScheme.Type = typeApiKey
		tokenScheme.In = cookie
		tokenScheme.Name = testCookieName

		jwtScheme := openapi3.NewSecurityScheme()
		jwtScheme.Type = typeHttp
		jwtScheme.Scheme = schemeBearer
		jwtScheme.BearerFormat = bearerFormatJWT

		oas.Components.SecuritySchemes = openapi3.SecuritySchemes{
			testSecurityNameToken: &openapi3.SecuritySchemeRef{
				Value: tokenScheme,
			},
		}

		oas.SetTykExtension(&XTykAPIGateway{})

		err := oas.importAuthentication()
		assert.NoError(t, err)

		authentication := oas.getTykAuthentication()

		assert.True(t, authentication.Enabled)

		expectedSecuritySchemes := SecuritySchemes{
			testSecurityNameToken: &Token{
				Enabled: true,
				AuthSources: AuthSources{
					Cookie: &AuthSource{
						Enabled: true,
					},
				},
			},
		}

		assert.Equal(t, expectedSecuritySchemes, authentication.SecuritySchemes)
	})

	t.Run("update existing one", func(t *testing.T) {
		oas := OAS{}
		oas.Security = openapi3.SecurityRequirements{
			{testSecurityNameToken: []string{}},
		}

		securityScheme := openapi3.NewSecurityScheme()
		securityScheme.Type = typeApiKey
		securityScheme.In = cookie
		securityScheme.Name = testCookieName

		oas.Components.SecuritySchemes = openapi3.SecuritySchemes{
			testSecurityNameToken: &openapi3.SecuritySchemeRef{
				Value: securityScheme,
			},
		}

		xTykAPIGateway := &XTykAPIGateway{
			Server: Server{
				Authentication: &Authentication{
					SecuritySchemes: SecuritySchemes{
						testSecurityNameToken: &Token{
							Enabled: false,
							AuthSources: AuthSources{
								Header: &AuthSource{
									Enabled: true,
									Name:    testHeaderName,
								},
							},
						},
					},
				},
			},
		}

		oas.SetTykExtension(xTykAPIGateway)

		err := oas.importAuthentication()
		assert.NoError(t, err)

		authentication := oas.getTykAuthentication()

		assert.True(t, authentication.Enabled)

		expectedSecuritySchemes := SecuritySchemes{
			testSecurityNameToken: &Token{
				Enabled: true,
				AuthSources: AuthSources{
					Header: &AuthSource{
						Enabled: true,
						Name:    testHeaderName,
					},
					Cookie: &AuthSource{
						Enabled: true,
					},
				},
			},
		}

		assert.Equal(t, expectedSecuritySchemes, authentication.SecuritySchemes)
	})
}

func TestSecuritySchemes_Import(t *testing.T) {
	const (
		testSecurityNameToken = "my_auth_token"
		testHeaderName        = "my-auth-token-header"
		testCookieName        = "my-auth-token-cookie"
	)

	t.Run("token", func(t *testing.T) {
		securitySchemes := SecuritySchemes{}
		nativeSecurityScheme := &openapi3.SecurityScheme{
			Type: typeApiKey,
			In:   header,
			Name: testHeaderName,
		}

		err := securitySchemes.Import(testSecurityNameToken, nativeSecurityScheme)
		assert.NoError(t, err)

		expectedToken := &Token{
			Enabled: true,
			AuthSources: AuthSources{
				Header: &AuthSource{
					Enabled: true,
				},
			},
		}

		assert.Equal(t, expectedToken, securitySchemes[testSecurityNameToken])
	})

	t.Run("update existing one", func(t *testing.T) {
		existingToken := &Token{
			AuthSources: AuthSources{
				Cookie: &AuthSource{
					Enabled: true,
					Name:    testCookieName,
				},
			},
		}
		securitySchemes := SecuritySchemes{
			testSecurityNameToken: existingToken,
		}

		nativeSecurityScheme := &openapi3.SecurityScheme{
			Type: typeApiKey,
			In:   header,
			Name: testHeaderName,
		}

		err := securitySchemes.Import(testSecurityNameToken, nativeSecurityScheme)
		assert.NoError(t, err)

		expectedToken := &Token{
			Enabled: true,
			AuthSources: AuthSources{
				Header: &AuthSource{
					Enabled: true,
				},
				Cookie: &AuthSource{
					Enabled: true,
					Name:    testCookieName,
				},
			},
		}

		assert.Equal(t, expectedToken, securitySchemes[testSecurityNameToken])
	})
}

func TestAuthSources_Import(t *testing.T) {
	expectedAuthSource := &AuthSource{Enabled: true}

	t.Run(header, func(t *testing.T) {
		as := AuthSources{}
		as.Import(header)

		assert.Equal(t, expectedAuthSource, as.Header)
	})

	t.Run(query, func(t *testing.T) {
		as := AuthSources{}
		as.Import(query)

		assert.Equal(t, expectedAuthSource, as.Query)
	})

	t.Run(cookie, func(t *testing.T) {
		as := AuthSources{}
		as.Import(cookie)

		assert.Equal(t, expectedAuthSource, as.Cookie)
	})
}
