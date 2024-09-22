package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/sirupsen/logrus"
)

var (
	verbose            = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()
    upstreamUrl        = kingpin.Flag("upstream.url", "upstream to proxy the request to").Required().String()
	listenAddr         = kingpin.Flag("proxy.listen-addr", "address the proxy will listen on").Required().String()

	urlPattern           = regexp.MustCompile(`^/([^/]+)(/api/v.+)$`)
    queryPathPattern     = regexp.MustCompile(`^/api/v1/(query|query_range|query_exemplars)$`)
    matchPathPattern     = regexp.MustCompile(`^/api/v1/(series|labels|label/[a-zA-Z_][a-zA-Z0-9_]*/values|)`)
	supportedPathPattern = regexp.MustCompile(`^/api/v1/(query|query_range|query_exemplars|series|label/[a-zA-Z0-9_]+/values)$`)
)

func handleQuery(filter string, values url.Values) (url.Values, error) {
    if values.Has("query") {
        filteredQuery, err := addQueryFilter(filter, values.Get("query"))
        if err != nil {
            return values, err
        }
        values.Set("query", filteredQuery)
    }
    return values, nil
}

func handleMatch(filter string, values url.Values) (url.Values, error) {
    if values.Has("match[]") {
        oldMatchers := values["match[]"]
        values.Del("match[]")
        for _, m := range oldMatchers {
            filtered, err := addQueryFilter(filter, m)
            if err != nil {
                return values, err
            }
            values.Add("match[]", filtered)
        }
    } else {
        values.Add("match[]", filter)
    }
    return values, nil
}

func handleValues(apiPath string, filter string, values url.Values) (url.Values, error) {
    if queryPathPattern.MatchString(apiPath) {
        return handleQuery(filter, values)
    } else if matchPathPattern.MatchString(apiPath) {
        return handleMatch(filter, values)
    }
    return values, nil
}

func handleAPIRequest(filter string, apiPath string, rw http.ResponseWriter, req *http.Request) error {
	log.WithFields(log.Fields{"method": req.Method, "path": req.URL.String(), "filter": filter}).Debug("handling request")

    req.ParseForm()

    newURL, err := url.Parse(*upstreamUrl)
    if err != nil {
        return err
    }
    newURL.Path = fmt.Sprintf("%s/%s", newURL.Path, apiPath)
    getValues, err := handleValues(apiPath, filter, req.Form)
    if err != nil {
        return err
    }
    newURL.RawQuery = getValues.Encode()

    var resp *http.Response
	log.WithFields(log.Fields{"url": newURL.String()}).Debug("starting request to upstream")
    if req.Method == "GET" {
        resp, err = http.Get(newURL.String())
        if err != nil {
            return err
        }
    } else {
        postValues, err := handleValues(apiPath, filter, req.PostForm)
        if err != nil {
            return err
        }
        resp, err = http.PostForm(newURL.String(), postValues)
        if err != nil {
            return err
        }
    }

	h := rw.Header()
	for k, vv := range resp.Header {
		if k == "Content-Length" {
			continue
		}
		for _, v := range vv {
			log.WithFields(log.Fields{"header": k, "value": v}).Debug("copying response header")
			h.Add(k, v)
		}
	}
    rw.WriteHeader(resp.StatusCode)
    _, err = io.Copy(rw, resp.Body)
    return err
}

func handleUnsupported(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusBadRequest)
	rw.Write([]byte("Unsupported\n"))
	log.WithFields(log.Fields{"method": r.Method, "path": r.URL.String()}).Warn("unsupported request")
}

type router struct {
}

func (r router) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" && req.Method != "POST" {
		rw.WriteHeader(http.StatusBadRequest)
		rw.Write([]byte("Unsupported method\n"))
		log.WithFields(log.Fields{"method": req.Method, "path": req.URL.String()}).Warn("unsupported method")
		return
	}
	path := req.URL.Path
	m := urlPattern.FindStringSubmatch(path)
	if len(m) != 3 {
		handleUnsupported(rw, req)
		return
	}

	filter := fmt.Sprintf("{ %s }", m[1])
	apiPath := m[2]

    err := handleAPIRequest(filter, apiPath, rw, req)
    if err != nil {
        rw.WriteHeader(http.StatusInternalServerError)
        rw.Write([]byte("Internal server error\n"))
        log.WithFields(log.Fields{"err": err}).Warn("Internal Error")
    }
}

func main() {
	kingpin.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	log.WithFields(log.Fields{"upstream.url": *upstreamUrl, "proxy.listen-addr": *listenAddr}).Info("Starting")
	router := router{}
	http.Handle("/", router)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}
