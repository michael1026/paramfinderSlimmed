package reflectedscanner

import (
	"strings"

	"github.com/michael1026/paramfinderSlimmed/types/scan"
	"golang.org/x/exp/maps"
)

func CheckDocForReflections(body string, urlInfo *scan.URLInfo) []string {
	foundParameters := make(map[string]struct{})
	canaryCount := CountReflections(body, urlInfo.CanaryValue)

	for param, value := range urlInfo.PotentialParameters {
		counted := CountReflections(body, value)

		if counted > canaryCount {
			foundParameters[param] = struct{}{}
			if len(foundParameters) > 50 {
				// Going to assume these are false positives. 50+ parameters should not exist on one URL
				return []string{}
			}
		}
	}

	return maps.Keys(foundParameters)
}

func CountReflections(body string, canary string) int {
	return strings.Count(body, canary)
}
