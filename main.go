package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {

	var domains []string

	var dates bool
	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")

	var noSubs bool
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")

	var getVersionsFlag bool
	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")

	var skipSourcesValue string
	flag.StringVar(&skipSourcesValue, "skip-sources", "", "comma-separated sources to skip (wayback, commoncrawl, virustotal)")

	var httpOnly bool
	flag.BoolVar(&httpOnly, "http-only", false, "only output HTTP and HTTPS URLs")

	flag.Parse()

	fetchers := defaultSourceFetchers()
	skippedSources, err := parseSkippedSources(skipSourcesValue, fetchers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if flag.NArg() > 0 {
		// fetch for a single domain
		domains = []string{flag.Arg(0)}
	} else {

		// fetch for all domains from stdin
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			domains = append(domains, sc.Text())
		}

		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}

	// get-versions mode
	if getVersionsFlag {

		for _, u := range domains {
			versions, err := getVersions(u)
			if err != nil {
				continue
			}
			fmt.Println(strings.Join(versions, "\n"))
		}

		return
	}

	for _, domain := range domains {
		processDomain(domain, noSubs, dates, httpOnly, fetchers, skippedSources, os.Stdout, os.Stderr)
	}

}

func processDomain(domain string, noSubs, dates, httpOnly bool, fetchers []sourceFetcher, skippedSources map[string]struct{}, stdout, stderr io.Writer) {
	var wg sync.WaitGroup
	wurls := make(chan wurl)

	for _, source := range fetchers {
		fetcher := source
		if _, skipped := skippedSources[fetcher.name]; skipped {
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			if fetcher.skipReason != nil {
				if fetcher.skipReason() != "" {
					return
				}
			}

			resp, err := fetcher.fetch(domain, noSubs)
			if err != nil {
				return
			}

			for _, r := range resp {
				if noSubs && isSubdomain(r.url, domain) {
					continue
				}
				wurls <- r
			}
		}()
	}

	go func() {
		wg.Wait()
		close(wurls)
	}()

	seen := make(map[string]bool)
	for w := range wurls {
		if httpOnly && !isHTTPURL(w.url) {
			continue
		}
		if _, ok := seen[w.url]; ok {
			continue
		}
		seen[w.url] = true

		if dates {

			d, err := time.Parse("20060102150405", w.date)
			if err != nil {
				fmt.Fprintf(stderr, "failed to parse date [%s] for URL [%s]\n", w.date, w.url)
			}

			fmt.Fprintf(stdout, "%s %s\n", d.Format(time.RFC3339), w.url)

		} else {
			fmt.Fprintln(stdout, w.url)
		}
	}
}

type wurl struct {
	date string
	url  string
}

type fetchFn func(string, bool) ([]wurl, error)

type sourceFetcher struct {
	name       string
	fetch      fetchFn
	skipReason func() string
}

func defaultSourceFetchers() []sourceFetcher {
	return []sourceFetcher{
		{name: "wayback", fetch: getWaybackURLs},
		{name: "commoncrawl", fetch: getCommonCrawlURLs},
		{name: "virustotal", fetch: getVirusTotalURLs, skipReason: virusTotalSkipReason},
	}
}

func parseSkippedSources(value string, fetchers []sourceFetcher) (map[string]struct{}, error) {
	validSources := make(map[string]struct{}, len(fetchers))
	validNames := make([]string, 0, len(fetchers))
	for _, fetcher := range fetchers {
		validSources[fetcher.name] = struct{}{}
		validNames = append(validNames, fetcher.name)
	}

	skippedSources := make(map[string]struct{})
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, valid := validSources[name]; !valid {
			return nil, fmt.Errorf("invalid source %q; valid sources: %s", name, strings.Join(validNames, ", "))
		}
		skippedSources[name] = struct{}{}
	}

	return skippedSources, nil
}

func virusTotalSkipReason() string {
	if os.Getenv("VT_API_KEY") == "" {
		return "VT_API_KEY is not set"
	}
	return ""
}

func isHTTPURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}

	return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
}

func getWaybackURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain),
	)
	if err != nil {
		return []wurl{}, err
	}

	raw, err := ioutil.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return []wurl{}, err
	}

	var wrapper [][]string
	err = json.Unmarshal(raw, &wrapper)

	out := make([]wurl, 0, len(wrapper))

	skip := true
	for _, urls := range wrapper {
		// The first item is always just the string "original",
		// so we should skip the first item
		if skip {
			skip = false
			continue
		}
		out = append(out, wurl{date: urls[1], url: urls[2]})
	}

	return out, nil

}

func getCommonCrawlURLs(domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	res, err := http.Get(
		fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain),
	)
	if err != nil {
		return []wurl{}, err
	}

	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)

	out := make([]wurl, 0)

	for sc.Scan() {

		wrapper := struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}{}
		err = json.Unmarshal([]byte(sc.Text()), &wrapper)

		if err != nil {
			continue
		}

		out = append(out, wurl{date: wrapper.Timestamp, url: wrapper.URL})
	}

	return out, nil

}

func getVirusTotalURLs(domain string, noSubs bool) ([]wurl, error) {
	out := make([]wurl, 0)

	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		// no API key isn't an error,
		// just don't fetch
		return out, nil
	}

	fetchURL := "https://www.virustotal.com/vtapi/v2/domain/report"
	req, err := http.NewRequest(http.MethodGet, fetchURL, nil)
	if err != nil {
		return out, err
	}

	query := req.URL.Query()
	query.Set("apikey", apiKey)
	query.Set("domain", domain)
	req.URL.RawQuery = query.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return out, fmt.Errorf("VirusTotal API v2 returned %s", resp.Status)
	}

	wrapper := struct {
		URLs []struct {
			URL string `json:"url"`
			// TODO: handle VT date format (2018-03-26 09:22:43)
			// Date string `json:"scan_date"`
		} `json:"detected_urls"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return out, err
	}

	for _, u := range wrapper.URLs {
		if u.URL == "" {
			continue
		}
		out = append(out, wurl{url: u.URL})
	}

	return out, nil
}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		// we can't parse the URL so just
		// err on the side of including it in output
		return false
	}

	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func getVersions(u string) ([]string, error) {
	out := make([]string, 0)

	resp, err := http.Get(fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s&output=json", u,
	))

	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	r := [][]string{}

	dec := json.NewDecoder(resp.Body)

	err = dec.Decode(&r)
	if err != nil {
		return out, err
	}

	first := true
	seen := make(map[string]bool)
	for _, s := range r {

		// skip the first element, it's the field names
		if first {
			first = false
			continue
		}

		// fields: "urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"
		if seen[s[5]] {
			continue
		}
		seen[s[5]] = true
		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
	}

	return out, nil
}
