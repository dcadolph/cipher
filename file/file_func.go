package file

// SkipFunc returns true if a file should be skipped (not encrypted/decrypted).
type SkipFunc func(fileName string) (skip bool, err error)
