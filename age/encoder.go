package age

import (
	"regexp"
)

type Encoder struct {
	ageKey            string
	shamirThreshold   int
	inputFmt          Format
	outputFmt         Format
	unencryptedRegex  *regexp.Regexp
	encryptedRegex    *regexp.Regexp
	unencryptedSuffix string
	encryptedSuffix   string
}
