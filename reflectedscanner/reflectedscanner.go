package reflectedscanner

import (
	"strings"

	"github.com/michael1026/paramfinderSlimmed/types/scan"
	"github.com/michael1026/paramfinderSlimmed/util"
)

func CheckStability(canary *string, body string, urlInfo *scan.URLInfo) {
	canaryCount := CountReflections(body, *canary)

	if urlInfo.CanaryCount != canaryCount {
		urlInfo.Stable = false
	}
}

func CheckDocForReflections(body string, urlInfo *scan.URLInfo) []string {
	var foundParameters []string

	// if CountReflections(body, urlInfo.CanaryValue) != urlInfo.CanaryCount {
	// 	// something happened with the response to cause the canary count to not be correct
	// 	// this is probably caused by a parameter included in the request
	// 	// for now, we are going to ignore this URL, but in the future, I'd like to find the parameter that caused this

	// 	return foundParameters
	// }

	canaryCount := CountReflections(body, urlInfo.CanaryValue)

	for param, value := range urlInfo.PotentialParameters {
		counted := CountReflections(body, value)

		if counted > canaryCount {
			foundParameters = util.AppendIfMissing(foundParameters, param)
		}
	}

	// Check to make sure 50 / 100 / 1000 etc parameters weren't "found" in a single request. This could be caused by
	// multiple things affecting the entire response (one parameter, site going down, etc).
	//
	// Another solution to this might be to use a canary for every request, then compare other parameters against the
	// query.
	//
	// Another solution might be to detect the page being much different, then find what caused that.
	if len(foundParameters) == urlInfo.MaxParams {
		return []string{}
	}

	return foundParameters
}

func CountReflections(body string, canary string) int {
	return strings.Count(body, canary)
}
