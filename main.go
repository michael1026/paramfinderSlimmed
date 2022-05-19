package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

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

var results map[string]scan.URLInfo
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

	// outputFile := flag.String("o", "", "File to output results to (.json)")
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
	// wg := &sync.WaitGroup{}
	stabilityChannel := make(chan Request, len(lines))
	stableChannel := make(chan string)
	stabilityRespChannel := make(chan Response)
	sizeCheckReqChannel := make(chan Request)
	readyToScanChannel := make(chan string)
	parameterURLChannel := make(chan Request)
	parameterRespChannel := make(chan Response)
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
	findReflections(parameterRespChannel)

	wg.Wait()

	// resultJson, err := util.JSONMarshal(scanInfo.JsonResults)

	// if err != nil {
	// 	log.Fatalf("Error marsheling json: %s\n", err)
	// }

	// err = ioutil.WriteFile(*outputFile, resultJson, 0644)
}

func findReflections(parameterResponses chan Response) {
	for resp := range parameterResponses {
		if entry, ok := results[resp.url]; ok {
			doc, err := goquery.NewDocumentFromResponse(resp.Response)

			if err != nil {
				continue
			}

			reflectedscanner.CheckDocForReflections(doc, &entry)

			if len(entry.FoundParameters) > 0 {
				for _, foundParam := range entry.FoundParameters {
					fmt.Println(foundParam)
				}
			}
		}
	}

	time.Sleep(10 * time.Second)
}

func getParameterResponses(parameterURLs chan Request, parameterResponses chan Response) {
	// defer close(parameterResponses)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for req := range parameterURLs {
				resp, err := client.Do(req.Request)
				// fmt.Println("requesting1 " + req.url)

				if err != nil {
					continue
				}

				parameterResponses <- Response{
					Response: resp,
					url:      req.url,
				}
			}

			wg.Done()
		}()
	}

	wg.Wait()
	close(parameterResponses)
}

func createParameterURLs(readyToScanChannel chan string, parameterURLChannel chan Request) {
	defer close(parameterURLChannel)

	for rawUrl := range readyToScanChannel {
		if entry, ok := results[rawUrl]; ok {
			queryStrings :=
				splitParametersIntoMaxSize(
					rawUrl,
					&entry.PotentialParameters,
					entry.MaxParams,
					entry.CanaryValue)

			for _, paramValues := range queryStrings {

				parsedUrl, err := url.Parse(rawUrl)

				if err != nil {
					continue
				}

				query := parsedUrl.Query()

				for param, value := range paramValues {
					query.Add(param, value)
				}

				parsedUrl.RawQuery = query.Encode()

				parameterURLChannel <- Request{
					url:     rawUrl,
					Request: createRequest(parsedUrl.String()),
				}
			}
		}
	}
}

func checkURLStability(stabilityRespChannel chan Response, stableChannel chan string) {
	defer close(stableChannel)

	for resp := range stabilityRespChannel {
		doc, err := goquery.NewDocumentFromResponse(resp.Response)

		if entry, ok := results[resp.url]; ok {
			if err != nil || doc == nil {
				entry.Stable = false
				results[resp.url] = entry
				continue
			}

			if entry.CanaryCount == 0 {
				entry.PotentialParameters = findPotentialParameters(doc)
				entry.CanaryCount = reflectedscanner.CountReflections(doc, entry.CanaryValue)
			}

			entry.NumberOfCheckedURLs++

			if entry.Stable == false {
				fmt.Println("url is unstable. Skipping.3")
				entry.Stable = false
				results[resp.url] = entry
				continue
			}

			if err != nil {
				fmt.Println("url is unstable. Skipping.4")
				entry.Stable = false
				results[resp.url] = entry
				continue
			}

			if entry.CanaryCount != reflectedscanner.CountReflections(doc, entry.CanaryValue) {
				fmt.Println("url is unstable. Skipping.")
				entry.Stable = false
				results[resp.url] = entry
				continue
			}

			if entry.NumberOfCheckedURLs == 5 {
				stableChannel <- resp.url
			}

			results[resp.url] = entry
		}
	}
}

func checkMaxURLSize(sizeCheckReqChannel chan Request, readyToScanURLs chan string) {
	defer close(readyToScanURLs)

	for req := range sizeCheckReqChannel {
		if entry, ok := results[req.url]; ok {
			currentMaxParams := len(req.Request.URL.Query()) - 50

			if entry.MaxParams != 100 {
				// already solved, move on.
				continue
			}

			resp, err := client.Do(req.Request)
			// fmt.Println("requesting3 " + req.url)

			if err != nil || resp.StatusCode != http.StatusOK {
				entry.MaxParams = currentMaxParams
				readyToScanURLs <- req.url
				results[req.url] = entry
				continue
			}

			results[req.url] = entry
		}
	}
}

func createMaxURLSizeRequests(stableReqChannel chan string, sizeCheckReqChannel chan Request) {
	defer close(sizeCheckReqChannel)

	for rawUrl := range stableReqChannel {
		if entry, ok := results[rawUrl]; ok {
			parsedUrl, err := url.Parse(rawUrl)

			if err != nil {
				fmt.Printf("Error parsing URL: %s\n", err)
				continue
			}

			// fmt.Println("requesting2 " + rawUrl)

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
		results[rawUrl] = scan.URLInfo{
			CanaryValue: canary,
			CanaryCount: 0,
			Stable:      true,
			MaxParams:   100,
		}

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
	// defer close(responses)
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			for req := range requests {
				if entry, ok := results[req.url]; ok {
					if entry.Stable == false {
						fmt.Println("url is unstable. Skipping.1")
						continue
					}

					resp, err := client.Do(req.Request)
					// fmt.Println("request " + req.url)

					if err != nil {
						fmt.Println("url is unstable. Skipping.2")
						entry.Stable = false

						continue
					}

					responses <- Response{
						url:      req.url,
						Response: resp,
					}
				}
			}
			wg.Done()
		}()
	}
	wg.Wait()

	close(responses)
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

func findPotentialParameters(doc *goquery.Document) map[string]string {
	parameters := make(map[string]string)
	doc.Find("input").Each(func(index int, item *goquery.Selection) {
		name, ok := item.Attr("name")

		if ok && len(name) > 0 && len(name) < 20 {
			parameters[name] = util.RandSeq(10)
		}
	})

	finalWordlist := keywordsFromRegex(doc)

	for _, word := range finalWordlist {
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
		matches := re.FindStringSubmatch(html)

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
