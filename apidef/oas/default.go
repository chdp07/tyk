package oas

import (
	"errors"
	"fmt"
	"net/url"
)

const (
	invalidServerURLFmt          = "Please update %q to be a valid url or pass a valid url with upstreamURL query param"
	unsupportedSecuritySchemeFmt = "unsupported security scheme: %s"
)

var (
	errEmptyServersObject = errors.New("servers object is empty in OAS")
	errInvalidUpstreamURL = errors.New("invalid upstream URL")
	errInvalidServerURL   = errors.New("Error validating servers entry in OAS")

	errEmptySecurityObject = errors.New("security object is empty in OAS")
)

type TykExtensionConfigParams struct {
	UpstreamURL    string
	ListenPath     string
	Authentication bool
}

func (s *OAS) BuildDefaultTykExtension(overRideValues TykExtensionConfigParams) error {
	xTykAPIGateway := s.GetTykExtension()

	if xTykAPIGateway == nil {
		xTykAPIGateway = &XTykAPIGateway{}
		s.SetTykExtension(xTykAPIGateway)
	}

	if xTykAPIGateway.Info.Name == "" {
		xTykAPIGateway.Info.Name = s.Info.Title
	}

	xTykAPIGateway.Info.State.Active = true
	xTykAPIGateway.Info.State.Internal = false

	if overRideValues.ListenPath != "" {
		xTykAPIGateway.Server.ListenPath.Value = overRideValues.ListenPath
	} else if xTykAPIGateway.Server.ListenPath.Value == "" {
		xTykAPIGateway.Server.ListenPath.Value = "/"
	}

	var upstreamURL string

	if overRideValues.UpstreamURL != "" {
		upstreamURL = overRideValues.UpstreamURL
	} else {
		if len(s.Servers) == 0 {
			return errEmptyServersObject
		}

		upstreamURL = s.Servers[0].URL
	}

	if err := getURLFormatErr(overRideValues.UpstreamURL != "", upstreamURL); err != nil {
		return err
	}

	xTykAPIGateway.Upstream.URL = upstreamURL

	if overRideValues.Authentication {
		err := s.importAuthentication()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *OAS) importAuthentication() error {
	if len(s.Security) == 0 {
		return errEmptySecurityObject
	}

	securityReq := s.Security[0]

	xTykAPIGateway := s.GetTykExtension()
	authentication := xTykAPIGateway.Server.Authentication
	if authentication == nil {
		authentication = &Authentication{}
		xTykAPIGateway.Server.Authentication = authentication
	}

	authentication.Enabled = true

	tykSecuritySchemes := authentication.SecuritySchemes
	if tykSecuritySchemes == nil {
		tykSecuritySchemes = make(SecuritySchemes)
		authentication.SecuritySchemes = tykSecuritySchemes
	}

	for name := range securityReq {
		securityScheme := s.Components.SecuritySchemes[name]
		err := tykSecuritySchemes.Import(name, securityScheme.Value)
		if err != nil {
			log.WithError(err).Errorf("Error while importing security scheme: %s", name)
		}
	}

	return nil
}

func (as *AuthSources) Import(in string) {
	source := &AuthSource{Enabled: true}

	switch in {
	case header:
		as.Header = source
	case cookie:
		as.Cookie = source
	case query:
		as.Query = source
	}
}

func getURLFormatErr(fromParam bool, upstreamURL string) error {
	parsedURL, err := url.Parse(upstreamURL)
	if err != nil || !parsedURL.IsAbs() {
		if fromParam {
			return errInvalidUpstreamURL
		}
		return fmt.Errorf("%w: %s", errInvalidServerURL, fmt.Sprintf(invalidServerURLFmt, parsedURL))
	}

	return nil
}
