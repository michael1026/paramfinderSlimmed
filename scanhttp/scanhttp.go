package scanhttp

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

func GetDocFromURL(rawUrl string, client *http.Client) (*goquery.Document, error) {
	req, err := http.NewRequest("GET", rawUrl, nil)

	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return nil, err
	}
	req.Close = true
	req.Header.Set("Connection", "close")
	req.Header.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0")
	req.Header.Add("Accept-Language", "en-US,en;q=0.9")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error executing request: %s\n", err)
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && len(resp.Header.Get("content-type")) >= 9 && resp.Header.Get("content-type")[:9] == "text/html" {
		doc, err := goquery.NewDocumentFromReader(resp.Body)

		if err != nil {
			fmt.Printf("Error reading doc: %s\n", err)
			return nil, err
		}

		return doc, nil
	}

	return nil, nil
}

func BuildHttpClient() (c *http.Client) {
	fastdialerOpts := fastdialer.DefaultOptions
	fastdialerOpts.EnableFallback = true
	dialer, err := fastdialer.NewDialer(fastdialerOpts)
	if err != nil {
		log.Fatal("Error building HTTP client")
		return nil
	}

	transport := &http.Transport{
		MaxIdleConns:      100,
		IdleConnTimeout:   time.Second * 10,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       dialer.Dial,
	}

	re := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := &http.Client{
		Transport:     transport,
		CheckRedirect: re,
		Timeout:       time.Second * 10,
	}

	return client
}
