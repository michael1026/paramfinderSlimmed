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

type Request struct {
	*http.Request
	url string
}

type Response struct {
	*http.Response
	url string
}

type FoundParameters struct {
	parameters []string
	url        string
}

var results map[string]scan.URLInfo
var resultsMutex *sync.RWMutex
var wordlist []string
var client *http.Client

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
	scanInfo := scan.Scan{}
	scanInfo.FillDefaults()
	results = make(map[string]scan.URLInfo)
	resultsMutex = &sync.RWMutex{}

	outputFile := flag.String("o", "", "File to output results to (.json)")
	wordlistFile := flag.String("w", "", "Wordlist file")
	// threads := flag.Int("t", 5, "Number of threads")

	flag.Parse()

	if *wordlistFile != "" {
		wordlist, _ = readWordlistIntoFile(*wordlistFile)
		scanInfo.WordList = wordlist
	}

	var lines []string

	s := bufio.NewScanner(os.Stdin)

	for s.Scan() {
		scanInfo.ScanResults[s.Text()] = &scan.URLInfo{}
		lines = append(lines, s.Text())
	}

	client = scanhttp.BuildHttpClient()
	stabilityChannel := make(chan Request, len(lines))
	stableChannel := make(chan string)
	stabilityRespChannel := make(chan Response)
	sizeCheckReqChannel := make(chan Request)
	readyToScanChannel := make(chan string)
	parameterURLChannel := make(chan Request)
	parameterRespChannel := make(chan Response)
	foundParametersChannel := make(chan FoundParameters)
	wg := sync.WaitGroup{}

	// create requests
	go addURLsToStabilityRequestChannel(lines, stabilityChannel)
	// send requests and get responses (possible issue. Not all responses are needed to determine stability)
	go getStabilityResponses(stabilityChannel, stabilityRespChannel)
	// check the stability responses to determine stability
	go checkURLStability(stabilityRespChannel, stableChannel)
	// add stable URLs to channel for determining max URL size
	go createMaxURLSizeRequests(stableChannel, sizeCheckReqChannel)
	// check for max URL size
	go checkMaxURLSize(sizeCheckReqChannel, readyToScanChannel)
	// create URLs to find parameters
	go createParameterURLs(readyToScanChannel, parameterURLChannel)
	// send requests to get responses
	go getParameterResponses(parameterURLChannel, parameterRespChannel)
	// check responses for reflections
	go findReflections(parameterRespChannel, foundParametersChannel)

	writeJsonResults(foundParametersChannel, *outputFile)

	wg.Wait()

}

func writeJsonResults(foundParamsChan chan FoundParameters, outputFile string) {
	jsonResults := make(map[string]scan.JsonResult)

	for paramResult := range foundParamsChan {
		if entry, ok := jsonResults[paramResult.url]; ok {
			entry.Params = append(entry.Params, paramResult.parameters...)

			jsonResults[paramResult.url] = entry
		} else {
			result := scan.JsonResult{
				Params: paramResult.parameters,
			}

			jsonResults[paramResult.url] = result
		}
	}

	resultJson, err := util.JSONMarshal(jsonResults)

	if err != nil {
		log.Fatalf("Unable to print to file: %s\n", err)
	}

	err = ioutil.WriteFile(outputFile, resultJson, 0644)

	if err != nil {
		log.Fatalf("Unable to print to file: %s\n", err)
	}
}

func findReflections(parameterResponses chan Response, foundParamsChan chan FoundParameters) {
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for resp := range parameterResponses {
				if entry, ok := loadResults(resp.url); ok {
					doc, err := goquery.NewDocumentFromResponse(resp.Response)

					if err != nil {
						continue
					}

					foundParams := reflectedscanner.CheckDocForReflections(doc, &entry)

					if len(foundParams) > 0 {
						for _, param := range foundParams {
							fmt.Printf("Found \"%s\" on %s\n", param, resp.url)
						}

						foundParamsChan <- FoundParameters{
							url:        resp.url,
							parameters: foundParams,
						}
					}
				}
			}
		}()
	}

	wg.Wait()
	close(foundParamsChan)
}

func getParameterResponses(parameterURLs chan Request, parameterResponses chan Response) {
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for req := range parameterURLs {
				resp, err := client.Do(req.Request)

				if err != nil {
					continue
				}

				defer resp.Body.Close()

				parameterResponses <- Response{
					Response: resp,
					url:      req.url,
				}

			}
		}()
	}

	wg.Wait()
	close(parameterResponses)
}

func createParameterURLs(readyToScanChannel chan string, parameterURLChannel chan Request) {
	defer close(parameterURLChannel)

	for rawUrl := range readyToScanChannel {
		if entry, ok := loadResults(rawUrl); ok {
			paramCount := 0
			totalCount := 0

			parsedUrl, err := url.Parse(rawUrl)

			if err != nil {
				continue
			}

			query := parsedUrl.Query()

			for name, value := range entry.PotentialParameters {
				query.Add(name, value)
				paramCount++
				totalCount++

				if paramCount == entry.MaxParams || totalCount == len(entry.PotentialParameters) {
					query.Add(util.RandSeq(6), entry.CanaryValue)

					parsedUrl.RawQuery = query.Encode()

					parameterURLChannel <- Request{
						url:     rawUrl,
						Request: createRequest(parsedUrl.String()),
					}

					paramCount = 0

					parsedUrl, err := url.Parse(rawUrl)

					if err != nil {
						fmt.Printf("Error with parsing %s\n", err)
						continue
					}

					query = parsedUrl.Query()
				}
			}
		}
	}
}

func checkURLStability(stabilityRespChannel chan Response, stableChannel chan string) {
	defer close(stableChannel)

	for resp := range stabilityRespChannel {
		doc, err := goquery.NewDocumentFromResponse(resp.Response)

		if entry, ok := loadResults(resp.url); ok {
			if err != nil || doc == nil {
				entry.Stable = false
				addToResults(resp.url, entry)
				continue
			}

			if entry.NumberOfCheckedURLs == 0 {
				entry.PotentialParameters = findPotentialParameters(doc)
				entry.CanaryCount = reflectedscanner.CountReflections(doc, entry.CanaryValue)
			}

			entry.NumberOfCheckedURLs++

			if entry.Stable == false {
				continue
			}

			if err != nil {
				fmt.Printf("%s is unstable. Skipping.\n", resp.url)
				entry.Stable = false
				addToResults(resp.url, entry)
				continue
			}

			if entry.CanaryCount != reflectedscanner.CountReflections(doc, entry.CanaryValue) {
				fmt.Printf("%s is unstable. Skipping.\n", resp.url)
				entry.Stable = false
				addToResults(resp.url, entry)
				continue
			}

			if entry.NumberOfCheckedURLs == 5 {
				stableChannel <- resp.url
			}

			addToResults(resp.url, entry)
		}
	}
}

func checkMaxURLSize(sizeCheckReqChannel chan Request, readyToScanURLs chan string) {
	defer close(readyToScanURLs)

	for req := range sizeCheckReqChannel {
		if entry, ok := loadResults(req.url); ok {
			currentMaxParams := len(req.Request.URL.Query()) - 50

			if entry.MaxParams != 100 {
				// already solved, move on.
				continue
			}

			resp, err := client.Do(req.Request)

			if err != nil || resp.StatusCode != http.StatusOK {
				entry.MaxParams = currentMaxParams
				readyToScanURLs <- req.url
				addToResults(req.url, entry)
				continue
			}

			addToResults(req.url, entry)
		}
	}
}

func createMaxURLSizeRequests(stableReqChannel chan string, sizeCheckReqChannel chan Request) {
	defer close(sizeCheckReqChannel)

	for rawUrl := range stableReqChannel {
		if entry, ok := loadResults(rawUrl); ok {
			parsedUrl, err := url.Parse(rawUrl)

			if err != nil {
				fmt.Printf("Error parsing URL: %s\n", err)
				continue
			}

			if err != nil {
				fmt.Printf("Error creating request")
				continue
			}

			query := parsedUrl.Query()
			// add canary back so we can check reflections later
			query.Add(util.RandSeq(6), entry.CanaryValue)

			// add 100 parameters to URL as a start
			for i := 0; i < 100; i++ {
				query.Set(util.RandSeq(7), util.RandSeq(7))
			}

			// add an additional 50 (15 times)
			for i := 0; i < 15; i++ {
				for i := 0; i < 50; i++ {
					query.Set(util.RandSeq(10), util.RandSeq(10))
				}

				parsedUrl.RawQuery = query.Encode()
				req, err := http.NewRequest("HEAD", parsedUrl.String(), nil)

				if err != nil {
					continue
				}

				sizeCheckReqChannel <- Request{
					url:     rawUrl,
					Request: req,
				}
			}
		}
	}
}

func createRequest(url string) *http.Request {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Close = true
	req.Header.Add("Connection", "close")
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")

	return req
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

func addURLsToStabilityRequestChannel(urls []string, reqChan chan Request) {
	defer close(reqChan)

	for _, rawUrl := range urls {
		canary := util.RandSeq(6)
		addToResults(rawUrl, scan.URLInfo{
			CanaryValue: canary,
			CanaryCount: 0,
			Stable:      true,
			MaxParams:   100,
		})

		for i := 0; i < 5; i++ {
			originalTestUrl, err := url.Parse(rawUrl)

			if err != nil {
				fmt.Printf("Error parsing URL: %s\n", err)
			}

			query := originalTestUrl.Query()
			query.Set(util.RandSeq(6), canary)
			originalTestUrl.RawQuery = query.Encode()

			req := createRequest(originalTestUrl.String())

			reqChan <- Request{req, rawUrl}
		}
	}
}

func getStabilityResponses(requests chan Request, responses chan Response) {
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for req := range requests {
				if entry, ok := loadResults(req.url); ok {
					if entry.Stable == false {
						fmt.Printf("%s is unstable. Skipping.\n", req.url)
						continue
					}

					resp, err := client.Do(req.Request)

					if err != nil {
						fmt.Printf("%s is unstable. Skipping.\n", req.url)
						entry.Stable = false

						continue
					}

					responses <- Response{
						url:      req.url,
						Response: resp,
					}
				}
			}
		}()
	}
	wg.Wait()

	close(responses)
}

/***********************************************************************
*
* Used to find possible parameter names by looking at the page source
*
************************************************************************/

func findPotentialParameters(doc *goquery.Document) map[string]string {
	parameters := make(map[string]string)
	doc.Find("input").Each(func(index int, item *goquery.Selection) {
		name, ok := item.Attr("name")

		if ok && len(name) > 0 && len(name) < 20 {
			parameters[name] = util.RandSeq(10)
		}
	})

	regexWordlist := keywordsFromRegex(doc)

	for _, word := range regexWordlist {
		parameters[word] = util.RandSeq(10)
	}

	for _, word := range wordlist {
		parameters[word] = util.RandSeq(10)
	}

	return parameters
}

/***********************************************************************
*
* Finds keywords by using some regex against the page source
*
************************************************************************/

func keywordsFromRegex(doc *goquery.Document) []string {
	html, err := doc.Html()
	var newWordlist []string = wordlist

	if err != nil {
		fmt.Printf("Error reading doc: %s\n", err)
	}

	regexs := [...]string{"\"[a-zA-Z_\\-]+\":", "[a-zA-Z_\\-]+:(\\d|{|\"|\\s)"}

	for _, regex := range regexs {
		re := regexp.MustCompile(regex)
		allMatches := re.FindAllStringSubmatch(html, -1)

		for _, matches := range allMatches {
			for _, match := range matches {
				match = strings.ReplaceAll(match, "\"", "")
				match = strings.ReplaceAll(match, "{", "")
				match = strings.ReplaceAll(match, ":", "")
				match = strings.ReplaceAll(match, " ", "")

				if match != "" {
					newWordlist = util.AppendIfMissing(wordlist, match)
				}
			}
		}
	}

	return newWordlist
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

	resp, err := client.Head(rawUrl)
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

		resp, err = client.Head(parsedUrl.String())

		if err != nil {
			return
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			scanInfo.MaxParams = maxParameters
			return
		}

		maxParameters += 50
	}

	scanInfo.MaxParams = 1500
}

func addToResults(key string, info scan.URLInfo) {
	resultsMutex.Lock()
	results[key] = info
	resultsMutex.Unlock()
}

func loadResults(key string) (value scan.URLInfo, ok bool) {
	resultsMutex.Lock()
	result, ok := results[key]
	resultsMutex.Unlock()
	return result, ok
}
