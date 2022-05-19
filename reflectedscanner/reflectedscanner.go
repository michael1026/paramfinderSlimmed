package reflectedscanner

import (
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/michael1026/paramfinderSlimmed/types/scan"
	"github.com/michael1026/paramfinderSlimmed/util"
)

func CheckStability(canary *string, doc *goquery.Document, urlInfo *scan.URLInfo) {
	canaryCount := CountReflections(doc, *canary)

	if urlInfo.CanaryCount != canaryCount {
		urlInfo.Stable = false
	}
}

func CheckDocForReflections(doc *goquery.Document, urlInfo *scan.URLInfo) bool {
	if CountReflections(doc, urlInfo.CanaryValue) != urlInfo.CanaryCount {
		// something happened with the response to cause the canary count to not be correct
		// this is probably caused by a parameter included in the request
		// for now, we are going to ignore this URL, but in the future, I'd like to find the parameter that caused this

		return true
	}

	var foundParameters []string
	for param, value := range urlInfo.PotentialParameters {
		counted := CountReflections(doc, value)

		if counted > urlInfo.CanaryCount {
			fmt.Printf("counted %d, actual %d\n", counted, urlInfo.CanaryCount)
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
	if len(foundParameters) != urlInfo.MaxParams {
		urlInfo.FoundParameters = append(urlInfo.FoundParameters, foundParameters...)
	}

	return false
}

func CountReflections(doc *goquery.Document, canary string) int {
	html, err := doc.Html()

	if err != nil {
		fmt.Printf("Error converting to HTML: %s\n", err)
	}

	return strings.Count(html, canary)
}
