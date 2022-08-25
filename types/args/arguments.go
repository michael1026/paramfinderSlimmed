package args

import "strings"

type HeaderArgs []string

func (h *HeaderArgs) Set(val string) error {
	*h = append(*h, val)
	return nil
}

func (h HeaderArgs) String() string {
	return strings.Join(h, ", ")
}
