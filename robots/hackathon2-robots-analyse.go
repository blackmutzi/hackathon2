package robots

import (
	"bufio"
	"log"
	"net/http"
	"strings"
)

func CheckHTTPStatusCode(domain string) error {

	response, err := http.Get(domain)
	if err != nil {
		return err
	}

	defer response.Body.Close()
	log.Println(domain, "Status-Code:", response.StatusCode)
	return err
}

func RobotsAnalyse() {

	var domain string
	domain = "https://facebook.com"

	response, err := http.Get(domain + "/robots.txt")
	if err != nil {
		log.Println(err)
		return
	}

	defer response.Body.Close()

	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		var line = scanner.Text()

		if disPos := strings.Index(line, "Disallow: "); disPos != -1 {
			line = strings.Replace(line, "Disallow: ", "", -1)
			CheckHTTPStatusCode(domain + line)
		}
	}
}
