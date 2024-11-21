package dtls

import (
	"crypto/tls"
	// "github.com/adalkiran/webrtc-nuts-and-bolts/src/config"
	// "github.com/adalkiran/webrtc-nuts-and-bolts/src/logging"
)

var (
	ServerCertificate            *tls.Certificate
	ServerCertificateFingerprint string
)

// export Init
func Init() {
	//logging.Infof(logging.ProtoDTLS, "Initializing self signed certificate for server...")
	_, err, _ := GenerateServerCertificate("localhost")
	if err != nil {
		panic(err)
	}
	//ServerCertificate = serverCertificate
	//ServerCertificateFingerprint = GetCertificateFingerprint(serverCertificate)
	//logging.Infof(logging.ProtoDTLS, "Self signed certificate created with fingerprint <u>%s</u>", ServerCertificateFingerprint)
	//logging.Descf(logging.ProtoDTLS, "This certificate is stored in dtls.ServerCertificate variable globally, it will be used while DTLS handshake, sending SDP, SRTP, SRTCP packets, etc...")
}
