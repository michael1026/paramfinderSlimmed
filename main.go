package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/michael1026/paramfinderSlimmed/reflectedscanner"
	"github.com/michael1026/paramfinderSlimmed/scanhttp"
	"github.com/michael1026/paramfinderSlimmed/types/scan"
	"github.com/michael1026/paramfinderSlimmed/util"

	"github.com/PuerkitoBio/goquery"
)

/***************************************
* Ideas....
* Break into different detection types (reflected, extra headers, number of each tag, etc)
* - Reflected done
* Check stability of each detection type for each URL - Done
* Ability to disable certain checks
* Check max URL length for each host - Done
* Write JSON as program runs
/***************************************/

func main() {
	var wordlist []string
	scanInfo := scan.Scan{}
	scanInfo.FillDefaults()

	outputFile := flag.String("o", "", "File to output results to (.json)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	threads := flag.Int("t", 5, "Number of threads")

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
		scanInfo.WordList = wordlist
	}

	urls := make(chan string)
	var lines []string

	s := bufio.NewScanner(os.Stdin)

	for s.Scan() {
		scanInfo.ScanResults[s.Text()] = &scan.URLInfo{}
		lines = append(lines, s.Text())
	}

	client := scanhttp.BuildHttpClient()
	wg_domains := &sync.WaitGroup{}

	for i := 0; i < *threads; i++ {
		wg_domains.Add(1)
		go findParameters(urls, client, &scanInfo, wg_domains)
	}

	for _, rawUrl := range lines {
		urls <- rawUrl
	}

	close(urls)
	wg_domains.Wait()

	resultJson, err := util.JSONMarshal(scanInfo.JsonResults)

	if err != nil {
		log.Fatalf("Error marsheling json: %s\n", err)
	}

	err = ioutil.WriteFile(*outputFile, resultJson, 0644)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = util.AppendIfMissing(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func readWordlistIntoFile(wordlistPath string) ([]string, error) {
	lines, err := readLines(wordlistPath)
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}
	return lines, err
}

func findParameters(urls chan string, client *http.Client, scanInfo *scan.Scan, wg_domains *sync.WaitGroup) {
	defer wg_domains.Done()

	canary := util.RandSeq(10)
	scanInfo.CanaryValue = util.RandSeq(6)

	for rawUrl := range urls {
		fmt.Printf("Currently scanning: %s\n", rawUrl)
		urlInfo := scanInfo.ScanResults[rawUrl]
		urlInfo.ReflectedScan = &scan.ReflectedScan{}

		for i := 0; i < 5; i++ {
			originalTestUrl, err := url.Parse(rawUrl)

			if err != nil {
				fmt.Printf("Error parsing URL: %s\n", err)
			}

			query := originalTestUrl.Query()
			query.Set(util.RandSeq(6), canary)
			originalTestUrl.RawQuery = query.Encode()

			doc, err := scanhttp.GetDocFromURL(originalTestUrl.String(), client)

			if err == nil && doc != nil {
				if i == 0 {
					reflectedscanner.PrepareScan(canary, doc, urlInfo.ReflectedScan)
					urlInfo.PotentialParameters = findPotentialParameters(doc, &scanInfo.WordList)
				} else if urlInfo.ReflectedScan.Stable {
					reflectedscanner.CheckStability(&canary, doc, urlInfo.ReflectedScan)
				}
			}
		}
		calculateMaxParameters(scanInfo.ScanResults[rawUrl], client, rawUrl)

		queryStrings :=
			splitParametersIntoMaxSize(
				rawUrl,
				&scanInfo.ScanResults[rawUrl].PotentialParameters,
				scanInfo.ScanResults[rawUrl].MaxParams,
				scanInfo.CanaryValue)

		wg_split := &sync.WaitGroup{}

		for paramValuesIndex, paramValues := range queryStrings {
			if scanInfo.ScanResults[rawUrl].ReflectedScan.Stable == false {
				fmt.Printf("URL %s is unstable. Skipping\n", rawUrl)
				continue
			}

			parsedUrl, err := url.Parse(rawUrl)

			if err != nil {
				continue
			}

			query := parsedUrl.Query()

			for param, value := range paramValues {
				query.Add(param, value)
			}

			parsedUrl.RawQuery = query.Encode()

			wg_split.Add(1)

			go func(paramValuesCopy *map[string]string) {
				defer wg_split.Done()

				doc, err := scanhttp.GetDocFromURL(parsedUrl.String(), client)

				if err != nil {
					return
				}

				if doc != nil {
					reflectedscanner.CheckDocForReflections(doc, scanInfo.ScanResults[rawUrl], scanInfo, *paramValuesCopy, rawUrl)
				}
			}(&queryStrings[paramValuesIndex])
		}

		wg_split.Wait()

		if len(scanInfo.ScanResults[rawUrl].ReflectedScan.FoundParameters) > 0 {
			scanInfo.JsonResults[rawUrl] = scan.JsonResult{Params: scanInfo.ScanResults[rawUrl].ReflectedScan.FoundParameters}
		}
	}
}

/************************************************************************
*
* Splits parameter list into multiple query strings based on size
*
*************************************************************************/

func splitParametersIntoMaxSize(rawUrl string, parameters *map[string]string, maxParams int, canaryValue string) (splitParameters []map[string]string) {
	i := 0

	paramValues := make(map[string]string)
	paramValues[util.RandSeq(6)] = canaryValue

	for name, value := range *parameters {
		if i == maxParams {
			i = 0
			splitParameters = append(splitParameters, paramValues)
			paramValues = make(map[string]string)
			paramValues[util.RandSeq(6)] = canaryValue
		}
		paramValues[name] = value
		i++
	}

	splitParameters = append(splitParameters, paramValues)

	return splitParameters
}

/***********************************************************************
*
* Used to find possible parameter names by looking at the page source
*
************************************************************************/

func findPotentialParameters(doc *goquery.Document, wordlist *[]string) map[string]string {
	parameters := make(map[string]string)
	doc.Find("input").Each(func(index int, item *goquery.Selection) {
		name, ok := item.Attr("name")

		if ok && len(name) > 0 && len(name) < 20 {
			parameters[name] = util.RandSeq(10)
		}
	})

	wordlist = keywordsFromRegex(doc, wordlist)

	for _, word := range *wordlist {
		parameters[word] = util.RandSeq(10)
	}

	return parameters
}

/***********************************************************************
*
* Finds keywords by using some regex against the page source
*
************************************************************************/

func keywordsFromRegex(doc *goquery.Document, wordlist *[]string) *[]string {
	html, err := doc.Html()
	var newWordlist []string = *wordlist

	if err != nil {
		fmt.Printf("Error reading doc: %s\n", err)
	}

	regexs := [...]string{"\"[a-zA-Z_\\-]+\":", "[a-zA-Z_\\-]+:(\\d|{|\"|\\s)"}

	for _, regex := range regexs {
		re := regexp.MustCompile(regex)
		matches := re.FindStringSubmatch(html)

		for _, match := range matches {
			match = strings.ReplaceAll(match, "\"", "")
			match = strings.ReplaceAll(match, "{", "")
			match = strings.ReplaceAll(match, ":", "")
			match = strings.ReplaceAll(match, " ", "")

			if match != "" {
				newWordlist = util.AppendIfMissing(*wordlist, match)
			}
		}
	}

	return &newWordlist
}

/***********************************************************************
*
* Calculates the max number of parameters before the page breaks
*
************************************************************************/

func calculateMaxParameters(scanInfo *scan.URLInfo, client *http.Client, rawUrl string) {
	maxParameters := 100
	parsedUrl, err := url.Parse(rawUrl)

	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
		return
	}

	resp, err := http.Head(rawUrl)
	if err != nil {
		fmt.Printf("Error executing request: %s\n", err)
		return
	}

	resp.Body.Close()

	query := parsedUrl.Query()

	for i := 0; i < 100; i++ {
		query.Set(util.RandSeq(7), util.RandSeq(7))
	}

	for i := 0; i < 15; i++ {
		for i := 0; i < 100; i++ {
			query.Set(util.RandSeq(10), util.RandSeq(10))
		}

		parsedUrl.RawQuery = query.Encode()

		resp, err = http.Head(parsedUrl.String())

		if err != nil || resp.StatusCode != http.StatusOK {
			scanInfo.MaxParams = maxParameters
			return
		}

		maxParameters += 50
	}

	scanInfo.MaxParams = 1500
}
