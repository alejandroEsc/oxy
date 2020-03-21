package forward

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http/httpguts"

)

const (
	debugPrefix = "AE: vulcand/oxy/forward/spdy: "
)

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

func (f *httpForwarder) serveSPDYReverseProxy(w http.ResponseWriter, req *http.Request) {
	f.log.Debugf("%s serveSPDYReverseProxy", debugPrefix)

	ctx := req.Context()
	if cn, ok := w.(http.CloseNotifier); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	outReq := req.Clone(ctx)
	if req.ContentLength == 0 {
		outReq.Body = nil // Issue 16036: nil Body for http.Transport retries
	}
	if outReq.Header == nil {
		outReq.Header = make(http.Header) // Issue 33142: historical behavior was to always allocate
	}

	f.modifyRequest(outReq, req.URL)
	outReq.Close = false

	f.log.Debugf("%s OutRequest: %v",debugPrefix, outReq)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outReq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outReq.Header.Set("X-Forwarded-For", clientIP)
	}

	// must clone and NextProtos to not use h2
	config := f.tlsClientConfig.Clone()
	config.NextProtos = []string{"h1"}

	spdyRountTripper := NewSpdyRoundTripper(config, true)

	res, err := spdyRountTripper.RoundTrip(outReq)
	if err != nil {
		f.log.Debugf("%s error retrieving response: %s", debugPrefix, err)
		return
	}
	// get the connection that produced the http response
	resConn := spdyRountTripper.RespondConn()

	f.log.Debugf("%s Res: %v",debugPrefix, res)

	// Deal with 101 Switching Protocols responses: (WebSocket, h2c, etc)
	if res.StatusCode == http.StatusSwitchingProtocols {
		f.log.Debugf("%s The response has a 101 switch protocol response, we are handling it now", debugPrefix)
		handleUpgradeResponse(w, outReq, res, resConn)
		return
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return strings.ToLower(h.Get("Upgrade"))
}

func handleUpgradeResponse(rw http.ResponseWriter, req *http.Request, res *http.Response, backConn net.Conn) {
	log.Debugf("%s handleUpgradeResponse", debugPrefix)
	log.Debugf("%s handler response: %v", debugPrefix, res)
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if reqUpType != resUpType {
		log.Debugf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
		return
	}

	copyHeader(rw.Header(), res.Header)

	log.Debugf("%s headers: %v", debugPrefix, rw.Header())

	hj, ok := rw.(http.Hijacker)
	if !ok {
		log.Debugf("can't switch protocols using non-Hijacker ResponseWriter type %T", rw)
		return
	}
	defer backConn.Close()
	conn, brw, err := hj.Hijack()
	if err != nil {
		log.Debugf("Hijack failed on protocol switch: %v", err)
		return
	}
	defer conn.Close()
	res.Body = nil // so res.Write only writes the headers; we have res.Body in backConn above
	if err := res.Write(brw); err != nil {
		log.Debugf("response write: %v", err)
		return
	}
	if err := brw.Flush(); err != nil {
		log.Debugf("response flush: %v", err)
		return
	}
	errc := make(chan error, 1)
	spc := switchProtocolCopier{user: conn, backend: backConn}
	go spc.copyToBackend(errc)
	go spc.copyFromBackend(errc)
	<-errc
	log.Debugf("%s handleUpgradeResponse -  done - ", debugPrefix)
	return
}

// switchProtocolCopier exists so goroutines proxying data back and
// forth have nice names in stacks.
type switchProtocolCopier struct {
	user, backend io.ReadWriter
}

func (c switchProtocolCopier) copyFromBackend(errc chan<- error) {
	_, err := io.Copy(c.user, c.backend)
	errc <- err
}

func (c switchProtocolCopier) copyToBackend(errc chan<- error) {
	_, err := io.Copy(c.backend, c.user)
	errc <- err
}
