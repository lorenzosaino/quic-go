package self_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	mrand "math/rand"
	"net/http"
	"time"

	_ "github.com/lucas-clemente/quic-clients" // download clients
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/integrationtests/tools/testserver"
	"github.com/lucas-clemente/quic-go/internal/protocol"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

var directions = []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing, quicproxy.DirectionBoth}

var _ = Describe("Drop tests", func() {
	var (
		client *http.Client
		proxy  *quicproxy.QuicProxy
	)

	startProxy := func(dropCallback quicproxy.DropCallback, version protocol.VersionNumber) {
		var err error
		proxy, err = quicproxy.NewQuicProxy("localhost:0", version, &quicproxy.Opts{
			RemoteAddr: "localhost:" + testserver.Port(),
			DropPacket: dropCallback,
		})
		Expect(err).ToNot(HaveOccurred())
	}

	downloadFile := func() {
		rsp, err := client.Get(fmt.Sprintf("https://quic.clemente.io:%d/prdata", proxy.LocalPort()))
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))
		data, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 30*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(testserver.PRData))
	}

	uploadFile := func() {
		rsp, err := client.Post(
			fmt.Sprintf("https://quic.clemente.io:%d/echo", proxy.LocalPort()),
			"text/plain",
			bytes.NewReader(testserver.PRData),
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))
		data, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, 30*time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal(testserver.PRData))
	}

	downloadHello := func() {
		rsp, err := client.Get(fmt.Sprintf("https://quic.clemente.io:%d/hello", proxy.LocalPort()))
		Expect(err).ToNot(HaveOccurred())
		Expect(rsp.StatusCode).To(Equal(200))
		data, err := ioutil.ReadAll(gbytes.TimeoutReader(rsp.Body, time.Second))
		Expect(err).ToNot(HaveOccurred())
		Expect(data).To(Equal([]byte("Hello, World!\n")))
	}

	deterministicDropper := func(p, interval, dropInARow uint64) bool {
		return (p % interval) < dropInARow
	}

	stochasticDropper := func(freq int) bool {
		return mrand.Int63n(int64(freq)) == 0
	}

	AfterEach(func() {
		Expect(proxy.Close()).To(Succeed())
		testserver.StopQuicServer()
	})

	versions := append(protocol.SupportedVersions, protocol.VersionTLS)
	for _, v := range versions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			BeforeEach(func() {
				testserver.StartQuicServer([]protocol.VersionNumber{version})
				client = &http.Client{
					Transport: &h2quic.RoundTripper{
						QuicConfig: &quic.Config{
							Versions: []protocol.VersionNumber{version},
						},
					},
				}
			})

			Context("during the crypto handshake", func() {
				for _, d := range directions {
					direction := d

					It(fmt.Sprintf("establishes a connection when the first packet is lost in %s direction", d), func() {
						fmt.Println("using client", client.Transport.(*h2quic.RoundTripper).QuicConfig.Versions)
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p == 1 && d.Is(direction)
						}, version)
						downloadHello()
					})

					It(fmt.Sprintf("establishes a connection when the second packet is lost in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p == 2 && d.Is(direction)
						}, version)
						downloadHello()
					})

					It(fmt.Sprintf("establishes a connection when 1/5 of the packets are lost in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return d.Is(direction) && stochasticDropper(5)
						}, version)
						downloadHello()
					})
				}
			})

			Context("after the crypto handshake", func() {
				for _, d := range directions {
					direction := d

					It(fmt.Sprintf("downloads a file when every 10th packet is dropped in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p >= 10 && d.Is(direction) && deterministicDropper(p, 10, 1)
						}, version)
						downloadFile()
					})

					It(fmt.Sprintf("downloads a file when 1/10th of all packet are dropped randomly in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p >= 10 && d.Is(direction) && stochasticDropper(10)
						}, version)
						downloadFile()
					})

					It(fmt.Sprintf("downloads a file when 5 packets every 100 packet are dropped in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p >= 10 && d.Is(direction) && deterministicDropper(p, 100, 5)
						}, version)
						downloadFile()
					})

					It(fmt.Sprintf("uploads a file when every 10th packet is dropped in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p >= 10 && d.Is(direction) && deterministicDropper(p, 10, 1)
						}, version)
						uploadFile()
					})

					It(fmt.Sprintf("uploads a file when 1/10th of all packet are dropped randomly in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p >= 10 && d.Is(direction) && stochasticDropper(10)
						}, version)
						uploadFile()
					})

					It(fmt.Sprintf("uploads a file when 5 packets every 100 packet are dropped in %s direction", d), func() {
						startProxy(func(d quicproxy.Direction, p uint64) bool {
							return p >= 10 && d.Is(direction) && deterministicDropper(p, 100, 5)
						}, version)
						uploadFile()
					})
				}
			})
		})
	}
})
