package forward

import (
	//"bufio"
	"io"
	"net/http/httputil"
	"net/url"
	"time"

	//"net"
	"net/http"
	"strings"

	//"github.com/amahi/spdy"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/utils"
	"k8s.io/apimachinery/pkg/util/httpstream"
	//sspdy "github.com/SlyMarbo/spdy"
	k8spdy "k8s.io/apimachinery/pkg/util/httpstream/spdy"
)

const (
	debugPrefix = "AE: vulcand/oxy/forward/spdy: "
)

// serveHTTP forwards spdy traffic
func (f *httpForwarder) serveSPDY(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {

	if f.log.GetLevel() >= log.DebugLevel {
		defer f.log.Debugf("%s vulcand/oxy/forward/spdy: done", debugPrefix)
	}


	f.log.Debugf("%s writting upgrade headers", debugPrefix)
	// Upgrade Connection
	w.Header().Add(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	w.Header().Add(httpstream.HeaderUpgrade, k8spdy.HeaderSpdy31)
	w.Header().Add(httpstream.HeaderProtocolVersion, "v4.channel.k8s.io")
	w.Header().Add(httpstream.HeaderProtocolVersion, "v3.channel.k8s.io")
	w.Header().Add(httpstream.HeaderProtocolVersion, "v2.channel.k8s.io")
	w.Header().Add(httpstream.HeaderProtocolVersion, "channel.k8s.io")
	w.WriteHeader(http.StatusSwitchingProtocols)

	start := time.Now().UTC()
	outReq := f.copySPDYRequest(req)

	revproxy := httputil.ReverseProxy{
		Director: func(r *http.Request) {
			f.modifySPDYRequest(r, req.URL)
		},
		Transport:      f.roundTripper,
		FlushInterval:  f.flushInterval,
		ModifyResponse: f.modifyResponse,
		BufferPool:     f.bufferPool,
	}

	// HERE we may want instead to have a reverse proxy, which we should look into doing that rather then serving this

	f.log.Debugf("%s create new k8spdy connection", debugPrefix)
	//session := spdy.NewServerSession(hijackedConn, &http.Server{})

	if f.log.GetLevel() >= log.DebugLevel {
		pw := utils.NewProxyWriter(w)
		revproxy.ServeHTTP(pw, outReq)

		if req.TLS != nil {
			f.log.Debugf("vulcand/oxy/forward/http: Round trip: %v, code: %v, Length: %v, duration: %v tls:version: %x, tls:resume:%t, tls:csuite:%x, tls:server:%v",
				req.URL, pw.StatusCode(), pw.GetLength(), time.Now().UTC().Sub(start),
				req.TLS.Version,
				req.TLS.DidResume,
				req.TLS.CipherSuite,
				req.TLS.ServerName)
		} else {
			f.log.Debugf("vulcand/oxy/forward/http: Round trip: %v, code: %v, Length: %v, duration: %v",
				req.URL, pw.StatusCode(), pw.GetLength(), time.Now().UTC().Sub(start))
		}
	} else {
		revproxy.ServeHTTP(w, outReq)
	}

	for key := range w.Header() {
		if strings.HasPrefix(key, http.TrailerPrefix) {
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			break
		}
	}
}

// bufWriter is a Writer interface that also has a Flush method.
type bufWriter interface {
	io.Writer
	Flush() error
}

// copySPDYRequest makes a copy of the specified request.
func (f *httpForwarder) copySPDYRequest(req *http.Request) (outReq *http.Request) {
	outReq = new(http.Request)
	*outReq = *req // includes shallow copies of maps, but we handle this below

	outReq.URL = utils.CopyURL(req.URL)
	outReq.URL.Scheme = req.URL.Scheme

	u := f.getUrlFromRequest(outReq)

	outReq.URL.Path = u.Path
	outReq.URL.RawPath = u.RawPath
	outReq.URL.RawQuery = u.RawQuery
	outReq.RequestURI = "" // Outgoing request should not have RequestURI

	outReq.URL.Host = req.URL.Host
	if !f.passHost {
		outReq.Host = req.URL.Host
	}

	outReq.Header = make(http.Header)

	// gorilla websocket use this header to set the request.Host tested in checkSameOrigin
	outReq.Header.Set("Host", outReq.Host)
	utils.CopyHeaders(outReq.Header, req.Header)
	utils.RemoveHeaders(outReq.Header, WebsocketDialHeaders...)

	if f.rewriter != nil {
		f.rewriter.Rewrite(outReq)
	}
	return outReq
}

// Modify the request to handle the target URL
func (f *httpForwarder) modifySPDYRequest(outReq *http.Request, target *url.URL) {
	outReq.URL = utils.CopyURL(outReq.URL)
	outReq.URL.Scheme = target.Scheme
	outReq.URL.Host = target.Host

	u := f.getUrlFromRequest(outReq)

	outReq.URL.Path = u.Path
	outReq.URL.RawPath = u.RawPath
	outReq.URL.RawQuery = u.RawQuery
	outReq.RequestURI = "" // Outgoing request should not have RequestURI

	outReq.Proto = "SPDY/3.1"
	outReq.ProtoMajor = 3
	outReq.ProtoMinor = 1

	if f.rewriter != nil {
		f.rewriter.Rewrite(outReq)
	}

	// Do not pass client Host header unless optsetter PassHostHeader is set.
	if !f.passHost {
		outReq.Host = target.Host
	}
}


// IsSPDYRequest determines if the specified HTTP request is a
// SPDY/3.1 handshake request
func IsSPDYRequest(req *http.Request) bool {
	log.Debugf("AE: Request PROTOCOL is: %s , source %s, path %s",req.Proto, req.Host, req.URL.Path)
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

// IsSPDYRequest determines if the specified HTTP request is a
// SPDY/3.1 handshake request
func requiresUpgradeSPDY(req *http.Request) bool {
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
