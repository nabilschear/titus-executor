package service

import (
	"context"
	x509 "crypto/x509"
	"fmt"
	"regexp"

	"github.com/pkg/errors"

	"google.golang.org/grpc/credentials"

	"github.com/Netflix/titus-executor/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	errNoAuth = errors.New("No authentication")
)

func (*vpcService) authFunc(ctx context.Context) (context.Context, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Internal, "Could not retrieve peer from context")
	}
	l := logger.G(ctx)
	if peer.AuthInfo != nil {
		l.Debug("Authenticating peers via authFunc")
	} else {
		l.Debug("not authenticating peers via AuthFuncOverride")

	}
	return ctx, nil
}

type titusVPCAgentServiceAuthFuncOverride struct {
	*vpcService
}

func (vpcService *titusVPCAgentServiceAuthFuncOverride) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Internal, "Could not retrieve peer from context")
	}
	if peer.AuthInfo == nil {
		// TODO: Log this
		return ctx, errNoAuth
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ctx, fmt.Errorf("Received unexpected authentication type: %s", peer.AuthInfo.AuthType())
	}
	sv := tlsInfo.GetSecurityValue().(*credentials.TLSChannelzSecurityValue)
	cert, err := x509.ParseCertificate(sv.RemoteCertificate)
	if err != nil {
		return ctx, errors.Wrap(err, "Cannot parse remote certificate")
	}
	err = vpcService.validateCert(cert)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to verify client cert")
	}
	return ctx, nil
}

func (vpcService *titusVPCAgentServiceAuthFuncOverride) validateCert(cert *x509.Certificate) error {
	// This first check only validates the chain of trust
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:     vpcService.TitusAgentCACertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return err
	}
	// The cert.Verify function is relativly limited in what it can verify.
	// It only can take in a single string and match it against DNS/CN.
	// We know we will need to match against a variety of incoming names,
	// so we check everything in a loop and return an error if nothing matched.
	validCNs := []string{`titusagent\..*`}
	for _, validCn := range validCNs {
		r, _ := regexp.Compile(validCn)
		if r.MatchString(cert.Subject.CommonName) {
			return nil
		}
		for _, san := range cert.DNSNames {
			if r.MatchString(san) {
				return nil
			}
		}
	}
	return errors.Errorf("Certificate's CN: %s and SANS: %s failed to match our allow list: %s", cert.Subject.CommonName, cert.DNSNames, validCNs)
}
