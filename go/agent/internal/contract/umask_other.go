//go:build !unix

package contract

func setUmask(int) int { return 0 }
