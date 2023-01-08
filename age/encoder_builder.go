package age

import (
	"fmt"
	"regexp"
)

type EncoderBuilder struct {
	ageKey            string
	shamirThreshold   int
	inputFmt          Format
	outputFmt         Format
	unencryptedRegex  *regexp.Regexp
	encryptedRegex    *regexp.Regexp
	unencryptedSuffix string
	encryptedSuffix   string
}

func (eb *EncoderBuilder) Build() (*Encoder, error) {

	if eb.ageKey == "" {
		return nil, &Error{
			Cause: fmt.Errorf("invalid age key: %w", ErrEmpty),
		}
	}

	if eb.unencryptedRegex == nil {
		eb.unencryptedRegex = regexp.MustCompile("")
	}

	if eb.encryptedRegex == nil {
		eb.encryptedRegex = regexp.MustCompile("")
	}

	return &Encoder{
		ageKey:            eb.ageKey,
		shamirThreshold:   eb.shamirThreshold,
		inputFmt:          eb.inputFmt,
		outputFmt:         eb.outputFmt,
		unencryptedRegex:  eb.unencryptedRegex,
		encryptedRegex:    eb.encryptedRegex,
		unencryptedSuffix: eb.unencryptedSuffix,
		encryptedSuffix:   eb.encryptedSuffix,
	}, nil
}

func (eb *EncoderBuilder) AgeKey(ak string) *EncoderBuilder {
	eb.ageKey = ak
	return eb
}

func (eb *EncoderBuilder) ShamirThreshold(st int) *EncoderBuilder {
	eb.shamirThreshold = st
	return eb
}

func (eb *EncoderBuilder) InputFmt(f Format) *EncoderBuilder {
	eb.inputFmt = f
	return eb
}

func (eb *EncoderBuilder) OutputFmt(f Format) *EncoderBuilder {
	eb.outputFmt = f
	return eb
}

func (eb *EncoderBuilder) UnencryptedRegex(r *regexp.Regexp) *EncoderBuilder {
	eb.unencryptedRegex = r
	return eb
}

func (eb *EncoderBuilder) EncryptedRegex(r *regexp.Regexp) *EncoderBuilder {
	eb.encryptedRegex = r
	return eb
}

func (eb *EncoderBuilder) UnencryptedSuffix(s string) *EncoderBuilder {
	eb.unencryptedSuffix = s
	return eb
}

func (eb *EncoderBuilder) EncryptedSuffix(s string) *EncoderBuilder {
	eb.encryptedSuffix = s
	return eb
}