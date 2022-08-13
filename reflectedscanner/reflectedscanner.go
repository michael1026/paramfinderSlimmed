package reflectedscanner

import (
	"strings"

	"github.com/michael1026/paramfinderSlimmed/types/scan"
	"github.com/michael1026/paramfinderSlimmed/util"
)

func CheckDocForReflections(body string, urlInfo *scan.URLInfo) []string {
	var foundParameters []string
	canaryCount := CountReflections(body, urlInfo.CanaryValue)

	for param, value := range urlInfo.PotentialParameters {
		counted := CountReflections(body, value)

		if counted > canaryCount {
			foundParameters = util.AppendIfMissing(foundParameters, param)
			if len(foundParameters) > 50 {
				// Going to assume these are false positives. 50+ parameters should not exist on one URL
				return []string{}
			}
		}
	}

	return foundParameters
}

func CountReflections(body string, canary string) int {
	return strings.Count(body, canary)
}
