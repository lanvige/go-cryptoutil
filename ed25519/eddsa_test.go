package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	applog "github.com/sirupsen/logrus"
)

// PKCS8 256
var Pubkey = `-----BEGIN 公钥-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAKd0PbKjNEFOMmYRHJ28ucRTELcEj/H3YFqcIreFTtmJAgMBAAE=
-----END 公钥-----
`

// PKCS8 256 私钥
var Pirvatekey = `-----BEGIN 私钥-----
MIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEAp3Q9sqM0QU4yZhEcnby5x
FMQtwSP8fdgWpwit4VO2YkCAwEAAQIgPSbBBUR+Z77jvsxO8/egqs8j8ueUBEb2Pa
36RXsloTUCEQDM7w8RrHnoJgqZqpbU7zyLAhEA0S5PP16b5KDwWSeI/zzguwIQKpY
nKIISF0cIfuRvUbKhfwIRAJjaHxxuNLonBBoRsqDXylsCDz30xZWMCKys0CuQJZQc
/g==
-----END 私钥-----
`

func Test_SetPublicKey(t *testing.T) {
	if err := Ed25519.SetPubKey(Pubkey); err != nil {
		t.Error(err)
	}
}

func Test_SetPrivateKey(t *testing.T) {
	if err := Ed25519.SetPriKey(Pirvatekey); err != nil {
		t.Error(err)
	}
}

func TestRSA256PKCS8KeyGen(t *testing.T) {
	priKey, pubKey, _ := GenerateKey()

	priKeyPem, _ := DumpPriKeyPKCS8Base64(priKey)
	pubKeyPem, _ := DumpPubPKCS8Base64(pubKey)

	abc := base64.StdEncoding.EncodeToString([]byte(*priKey))
	abchex := hex.EncodeToString([]byte(*priKey))

	// 私钥 64，公钥 32 byte
	// 所以 hex 是 128
	applog.Info(len([]byte(*priKey)))
	applog.Info(len([]byte(*pubKey)))
	applog.Info(priKeyPem)
	applog.Warn(pubKeyPem)
	applog.Warn(abc)
	applog.Warn(abchex)
}

// 私钥加密公钥解密
func Test_PriSignPubVer(t *testing.T) {
	applog.Info("1")
	if err := Ed25519.SetPubKey(Pubkey); err != nil {
		applog.Info("1")
		return
		t.Error(err)
	}

	applog.Info("2")
	if err := Ed25519.SetPriKey(Pirvatekey); err != nil {
		applog.Info("2")

		t.Error(err)
	}

	applog.Info("3")
	prienctypt, err := Ed25519.SignWithSha1Base64([]byte(`hello world`))
	if err != nil {
		t.Error(err)
	}

	applog.Info(prienctypt)

	// base64content := base64.StdEncoding.EncodeToString(prienctypt)
	// applog.Info(base64content)

	// err2 := Ed25519.VerySignWithSha1Base64(`hello world`, prienctypt)
	// if err2 != nil {
	// 	t.Error(err2)
	// }

	applog.Info("success")
}
