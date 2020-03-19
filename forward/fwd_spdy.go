package forward

import (
	//"bufio"
	//"io"
	//"net/http/httputil"
	//"time"

	//"fmt"
	//"net/http/httputil"
	"net/url"
	"strings"

	//"time"

	//"net"
	"net/http"
	//"strings"

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
		defer f.log.Debugf("%s - done - ", debugPrefix)
	}

	// SO WE NEED TO DIAL. GET THE STREAMING SUPPORT FROM THE INDIVIDUAL WE ARE DIALING
	// INJECT THOSE HERE, MAYBE PART OF THE REQUEST?
	// THEN WE NEED TO HAVE THE TRANSFER OF DATA TO HAPPEN.

	//session := spdy.NewServerSession(conn, &http.Server{})
	//f.log.Debugf("%s serve", debugPrefix)

	//f.log.Debugf("%s Headers are: %v", debugPrefix, req.Header)
	//
	//f.log.Debugf("%s writting upgrade headers", debugPrefix)

	//hijacker, ok := w.(http.Hijacker)
	//if !ok {
	//	w.WriteHeader(http.StatusInternalServerError)
	//	f.log.Debugf("%s unable to upgrade: unable to hijack response", debugPrefix)
	//	return
	//}

	// Upgrade Connection
	//w.Header().Add(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	//w.Header().Add(httpstream.HeaderUpgrade, k8spdy.HeaderSpdy31)
	////
	////// the protocal stream version
	//for _, p := range req.Header[httpstream.HeaderProtocolVersion] {
	//	w.Header().Add(httpstream.HeaderProtocolVersion, p)
	//}
	//w.WriteHeader(http.StatusSwitchingProtocols)


	//conn, _, err := hijacker.Hijack()
	//if err != nil {
	//	f.log.Debugf("%s unable to upgrade: error hijacking response: %v", debugPrefix, err)
	//	return
	//}

	upgrader := k8spdy.NewResponseUpgrader()

	spdyConn := upgrader.UpgradeResponse(w, req, func(s httpstream.Stream, replySent <-chan struct{}) error {return nil})
	defer spdyConn.Close()

	// blocks until connection is done
	<- spdyConn.CloseChan()

	//
	//sRoundTripper := k8spdy.NewSpdyRoundTripper(f.tlsClientConfig, false)
	//
	//resp, err := sRoundTripper.RoundTrip(req)
	//if err != nil {
	//	f.log.Debugf("%s roundtripper error: %s", debugPrefix, err)
	//	return
	//}
	//
	//conn, err := sRoundTripper.NewConnection(resp)
	//if err != nil {
	//	f.log.Debugf("%s getting a new connection error: %s", debugPrefix, err)
	//	return
	//}
	//defer conn.Close()

	//
	//start := time.Now().UTC()
	//outReq := f.copySPDYRequest(req)
	//
	//revproxy := httputil.ReverseProxy{
	//	Director: func(r *http.Request) {
	//		f.modifySPDYRequest(r, req.URL)
	//	},
	//	Transport:      f.roundTripper,
	//	FlushInterval:  f.flushInterval,
	//	ModifyResponse: f.modifyResponse,
	//	BufferPool:     f.bufferPool,
	//}
	//
	//// HERE we may want instead to have a reverse proxy, which we should look into doing that rather then serving this
	//
	//f.log.Debugf("%s create new k8spdy connection", debugPrefix)
	////session := spdy.NewServerSession(hijackedConn, &http.Server{})
	//
	//if f.log.GetLevel() >= log.DebugLevel {
	//	pw := utils.NewProxyWriter(w)
	//	revproxy.ServeHTTP(pw, outReq)
	//
	//	if req.TLS != nil {
	//		f.log.Debugf("vulcand/oxy/forward/http: Round trip: %v, code: %v, Length: %v, duration: %v tls:version: %x, tls:resume:%t, tls:csuite:%x, tls:server:%v",
	//			req.URL, pw.StatusCode(), pw.GetLength(), time.Now().UTC().Sub(start),
	//			req.TLS.Version,
	//			req.TLS.DidResume,
	//			req.TLS.CipherSuite,
	//			req.TLS.ServerName)
	//	} else {
	//		f.log.Debugf("vulcand/oxy/forward/http: Round trip: %v, code: %v, Length: %v, duration: %v",
	//			req.URL, pw.StatusCode(), pw.GetLength(), time.Now().UTC().Sub(start))
	//	}
	//} else {
	//	revproxy.ServeHTTP(w, outReq)
	//}
	//
	//for key := range w.Header() {
	//	if strings.HasPrefix(key, http.TrailerPrefix) {
	//		if fl, ok := w.(http.Flusher); ok {
	//			fl.Flush()
	//		}
	//		break
	//	}
	//}
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

