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
	"time"

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

	f.handleViaStreams(w, req, ctx)
}

func (f *httpForwarder) handleConnection(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	f.log.Debugf("%s writting upgrade headers", debugPrefix)

	// Upgrade Connection
	w.Header().Add(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	w.Header().Add(httpstream.HeaderUpgrade, k8spdy.HeaderSpdy31)

	// the protocal stream version
	f.log.Debugf("%s supported protocol versions: %v", debugPrefix, req.Header[httpstream.HeaderProtocolVersion])

	for _, p := range req.Header[httpstream.HeaderProtocolVersion] {
		w.Header().Add(httpstream.HeaderProtocolVersion, p)
	}

	w.WriteHeader(http.StatusSwitchingProtocols)

	//hijacker, ok := w.(http.Hijacker)
	//if !ok {
	//	w.WriteHeader(http.StatusInternalServerError)
	//	f.log.Debugf("%s unable to upgrade: unable to hijack response", debugPrefix)
	//	return
	//}



	//conn, _, err := hijacker.Hijack()
	//if err != nil {
	//	f.log.Debugf("%s unable to upgrade: error hijacking response: %v", debugPrefix, err)
	//	return
	//}
}

func (f *httpForwarder) handleViaStreams(w http.ResponseWriter, req *http.Request, ctx *handlerContext) {
	streamChan := make(chan httpstream.Stream, 1)

	upgrader := k8spdy.NewResponseUpgrader()

	spdyConn := upgrader.UpgradeResponse(w, req, streamReceived(streamChan))
	if spdyConn == nil {
		return
	}
	defer spdyConn.Close()

	h := &StreamHandler{
		conn:                  spdyConn,
		streamChan:            streamChan,
		streamPairs:           make(map[string]*StreamPair),
		streamCreationTimeout: 1*time.Minute,
	}
	h.run()

	// blocks until connection is done
	//<- spdyConn.CloseChan()
}

func streamReceived(streams chan httpstream.Stream) func(httpstream.Stream, <-chan struct{}) error {
	return func(stream httpstream.Stream, replySent <-chan struct{}) error {
		streams <- stream
		return nil
	}
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

