package scanhttp

import (
	"crypto/tls"
	"log"
	"net/http"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
)

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
