package service

import (
	x509 "crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"

	"gotest.tools/assert"
)

func loadCert(filename string) *x509.Certificate {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	pem, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

func getTestVpcService() titusVPCAgentServiceAuthFuncOverride {
	titusAgentCACertPool := x509.NewCertPool()
	data, err := ioutil.ReadFile("test_certs/test-CA.pem")
	if err != nil {
		panic(err)
	}
	titusAgentCACertPool.AppendCertsFromPEM(data)
	mockService := vpcService{db: nil, TitusAgentCACertPool: titusAgentCACertPool}

	vpcService := &titusVPCAgentServiceAuthFuncOverride{
		vpcService: &mockService,
	}
	return *vpcService
}
func Test_titusVPCAgentServiceAuthFuncOverride_validateCert(t *testing.T) {
	vpcService := getTestVpcService()
	var err error

	goodCert := loadCert("test_certs/test-goodcn.crt")
	err = vpcService.validateCert(goodCert)
	assert.NilError(t, err)

	dnsName := loadCert("test_certs/test-dnsname.crt")
	err = vpcService.validateCert(dnsName)
	assert.NilError(t, err)

	expiredCert := loadCert("test_certs/test-leaf-expired.crt")
	err = vpcService.validateCert(expiredCert)
	assert.ErrorContains(t, err, "certificate has expired")

	badName := loadCert("test_certs/test-bad-name.crt")
	err = vpcService.validateCert(badName)
	assert.ErrorContains(t, err, "failed to match our allow list")
}
