// Copyright 2013, Rick Gibson.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// certutil is a package containing functions that simplify the interaction with ssl certificates
package certutil

import (
  "fmt"
  "errors"
  "encoding/pem"
  "crypto/x509"
  "io"
  "bufio"
  "os"
  "time"
)

var ErrNotBefore = errors.New("NotBefore date is a future date")
var ErrExpired = errors.New("Certificate has expired")

type CertDateError struct {
    Where string
    Date time.Time
    Err error
}

func (e *CertDateError) Error() string {
   return fmt.Sprintf("error: certutil.%s: %s: %v",e.Where,e.Err.Error(),e.Date)
}

func notBeforeError(w string, d time.Time) *CertDateError {
   return &CertDateError{w, d, ErrNotBefore}
}

func expiredError(w string, d time.Time) *CertDateError {
   return &CertDateError{w, d, ErrExpired}
}

func GetCert(f string) (*x509.Certificate, error) {
   fInfo, err := os.Stat(f)
   if err != nil { return nil, err }
   fi, err := os.Open(f)
   if err != nil { return nil, err }
   defer fi.Close()
   reader := bufio.NewReader(fi)
   cert_bytes := make([]byte,fInfo.Size())
   _, err = reader.Read(cert_bytes)
   if err != nil && err != io.EOF { return nil, err }
   block, p := pem.Decode(cert_bytes)
   if len(p) > 0 {
      fmt.Printf("Warning another certificate exists. (%d)\n",len(p))
   }
   cert, err := x509.ParseCertificates(block.Bytes)
   if err != nil { return nil, err }
   return cert[0], nil
}

func CheckCert(c *x509.Certificate) error {
   now := time.Now()
   if now.Before(c.NotBefore) {
      return notBeforeError("CheckCert", c.NotBefore)
   }
   if now.After(c.NotAfter) {
      return expiredError("CheckCert", c.NotAfter)
   }
   if c.Issuer.CommonName == c.Subject.CommonName && c.IsCA == false {
      return errors.New("certutil.CheckCert: This certificate is not properly self-signed.")
   }
   return nil
}

