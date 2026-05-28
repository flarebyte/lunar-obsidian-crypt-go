package lunarcrypt

import (
	"fmt"
	"slices"
	"strings"
)

func composeFullToken(prefix string, token string) string {
	return prefix + ":" + token
}

func extractTokenPrefix(fullToken string, allowedPrefixes []string) (string, string, *CryptError) {
	prefix, token, err := splitFullToken(fullToken)
	if err != nil {
		return "", "", err
	}
	if !slices.Contains(allowedPrefixes, prefix) {
		return "", "", tokenExtractionError("The token prefix is not supported")
	}
	return prefix, token, nil
}

func extractToken(expectedPrefix string, fullToken string) (string, *CryptError) {
	prefix, token, err := splitFullToken(fullToken)
	if err != nil {
		return "", err
	}
	if prefix != expectedPrefix {
		return "", tokenExtractionError("The token prefix does not match the expected prefix")
	}
	return token, nil
}

func splitFullToken(fullToken string) (string, string, *CryptError) {
	separator := strings.LastIndexByte(fullToken, ':')
	if separator < 0 {
		return "", "", tokenExtractionError("The full token must include a prefix and token separator")
	}

	prefix := fullToken[:separator]
	token := fullToken[separator+1:]
	if prefix == "" {
		return "", "", tokenExtractionError("The token prefix is required")
	}
	if token == "" {
		return "", "", tokenExtractionError("The JWT token is required")
	}
	return prefix, token, nil
}

func tokenExtractionError(message string) *CryptError {
	return &CryptError{
		Step:    StepVerifyIDExtractToken,
		Message: message,
	}
}

func unsupportedPrefixError(prefix string) *CryptError {
	return tokenExtractionError(fmt.Sprintf("The token prefix %q is not supported", prefix))
}
