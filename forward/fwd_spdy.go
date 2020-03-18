package forward

import (
	//"bufio"
	"io"
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

	// upgrade the connection
	f.log.Debugf("%s hijacking connection", debugPrefix)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "unable to upgrade: unable to hijack response", http.StatusInternalServerError)
		f.log.Errorf("%s error: unable to upgrade: unable to hijack response", debugPrefix)
		return
	}

	f.log.Debugf("%s writting upgrade headers", debugPrefix)

	w.Header().Add(httpstream.HeaderConnection, httpstream.HeaderUpgrade)
	w.Header().Add(httpstream.HeaderUpgrade, k8spdy.HeaderSpdy31)
	w.WriteHeader(http.StatusSwitchingProtocols)

	f.log.Debugf("%s do the hijacking", debugPrefix)
	hijackedConn, _, err := hijacker.Hijack()
	if err != nil {
		f.log.Errorf("%s error: unable to upgrade: unable to hijack and get connection %s", debugPrefix, err)
		return
	}

	//f.log.Debugf("%s create the connection, this may be wrong", debugPrefix)
	//conn := &rwConn{
	//	Conn:      hijackedConn,
	//	Reader:    io.MultiReader(rw),
	//	BufWriter: newSettingsAckSwallowWriter(rw.Writer),
	//}


	// items todo when complete
	doafter := func(){
		hijackedConn.Close()
		f.log.Debugf("%s closing items, completed.", debugPrefix)
	}

	// HERE we may want instead to have a reverse proxy, which we should look into doing that rather then serving this

	f.log.Debugf("%s create new k8spdy connection", debugPrefix)
	//session := spdy.NewServerSession(hijackedConn, &http.Server{})

	streamChan := make(chan httpstream.Stream)
	replySentChan := make(chan (<-chan struct{}))
	f.log.Debugf("%s creating k8spdy connection.", debugPrefix)
	_, err = k8spdy.NewServerConnection(hijackedConn, func(stream httpstream.Stream, replySent <-chan struct{}) error {
		streamChan <- stream
		replySentChan <- replySent
		return nil
	})
	if err != nil {
		f.log.Errorf("server: error creating spdy connection: %v", err)
	}

	stream := <-streamChan
	replySent := <-replySentChan
	<-replySent

	buf := make([]byte, 1)
	_, err = stream.Read(buf)
	if err != io.EOF {
		f.log.Errorf("server: unexpected read error: %v", err)
	}

	//f.log.Debugf("%s serve", debugPrefix)
	//session.Serve()

	defer doafter()
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
