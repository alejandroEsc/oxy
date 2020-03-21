package forward

import (
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	debugPrefix = "AE: vulcand/oxy/forward/spdy: "
)

// serveHTTP forwards spdy traffic
func (f *httpForwarder) serveSPDY(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {

	if f.log.GetLevel() >= log.DebugLevel {
		defer f.log.Debugf("%s - done - ", debugPrefix)
	}

	f.handleViaReverseProxy(w, req, ctx)
}

// IsSPDYRequest determines if the specified HTTP request is a
// SPDY/3.1 handshake request
func IsSPDYRequest(req *http.Request) bool {
	containsHeader := func(name, value string) bool {
		items := strings.Split(req.Header.Get(name), ",")
		for _, item := range items {
			if value == strings.ToLower(strings.TrimSpace(item)) {
				return true
			}
		}
		return false
	}

	return containsHeader(Connection, "upgrade") && containsHeader(Upgrade, "spdy/3.1")
}




