package main

import (
  "fmt"
  "os"
  "wrg/certutil"
)

func main() {
   cert, err := certutil.GetCert(os.Args[1])
   if err != nil { panic(err) }
   fmt.Println("Certificate info:")
   fmt.Printf(" Issuer CN: %s\n", cert.Issuer.CommonName)
   fmt.Printf(" Version: %d\n",cert.Version)
   fmt.Printf(" Serial: %v\n",cert.SerialNumber)
   fmt.Printf(" Host: %s\n", cert.Subject.CommonName)
   fmt.Printf(" KeyAlgo: %d\n", cert.PublicKeyAlgorithm)
   fmt.Printf(" KeyUsage: %d\n", cert.KeyUsage)
   fmt.Printf(" IsCA: %v\n", cert.IsCA)
   err = cert.VerifyHostname(os.Getenv("HOSTNAME"))
   if err != nil { fmt.Println(err) }
   if err = certutil.CheckCert(cert); err != nil {
      fmt.Println(err.Error())
   } else {
      fmt.Println("Hooray a valid certificate!")
   }
}
  
