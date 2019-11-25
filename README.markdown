# Onion x509

This repository contains a set of command-line utilities for bridging the gap
between Onion services and x509.

Everything in this repository should be considered experimental.

## Installation

Please install this tool using Go's own package management tool:

    $ go get github.com/ahf/onion-x509/cmd/onion-x509

## Usage

1. The first thing we have to do is to create a new Onion Service using Tor.
   The easiest way to achieve this is to let Tor do all the work for us.

   We add the following two lines to an empty `torrc` file:

       HiddenServiceDir onion-service-test/
       HiddenServicePort 80 127.0.0.1:80

   We start Tor with our new configuration file:

       $ tor -f torrc
       Nov 25 01:13:13.023 [notice] Tor 0.4.1.6 running on Linux with Libevent 2.1.11-stable, OpenSSL 1.1.1d, Zlib 1.2.11, Liblzma 5.2.4, and Libzstd 1.4.4.
       Nov 25 01:13:13.024 [notice] Tor can't help you if you use it wrong! Learn how to be safe at https://www.torproject.org/download/download#warning
       Nov 25 01:13:13.024 [warn] Tor was compiled with zstd 1.4.3, but is running with zstd 1.4.4. For safety, we'll avoid using advanced zstd functionality.
       Nov 25 01:13:13.024 [notice] Read configuration file "/home/user/torrc".
       Nov 25 01:13:13.026 [warn] Path for HiddenServiceDir (onion-service-test/) is relative and will resolve to /home/user/onion-service-test/. Is this what you wanted?
       Nov 25 01:13:13.026 [notice] Opening Socks listener on 127.0.0.1:9050
       Nov 25 01:13:13.026 [notice] Opened Socks listener on 127.0.0.1:9050
       Nov 25 01:13:13.000 [notice] Parsing GEOIP IPv4 file /usr/share/tor/geoip.
       Nov 25 01:13:13.000 [notice] Parsing GEOIP IPv6 file /usr/share/tor/geoip6.
       Nov 25 01:13:13.000 [notice] Bootstrapped 0% (starting): Starting
       Nov 25 01:13:13.000 [notice] Starting with guard context "default"
       Nov 25 01:13:14.000 [notice] Bootstrapped 5% (conn): Connecting to a relay
       Nov 25 01:13:14.000 [notice] Bootstrapped 10% (conn_done): Connected to a relay
       Nov 25 01:13:14.000 [notice] Bootstrapped 14% (handshake): Handshaking with a relay
       Nov 25 01:13:14.000 [notice] Bootstrapped 15% (handshake_done): Handshake with a relay done
       Nov 25 01:13:14.000 [notice] Bootstrapped 20% (onehop_create): Establishing an encrypted directory connection
       Nov 25 01:13:14.000 [notice] Bootstrapped 25% (requesting_status): Asking for networkstatus consensus
       Nov 25 01:13:14.000 [notice] Bootstrapped 30% (loading_status): Loading networkstatus consensus
       Nov 25 01:13:14.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors
       Nov 25 01:13:14.000 [notice] I learned some more directory information, but not enough to build a circuit: We need more microdescriptors: we have 4610/6080, and can only build 54% of likely paths. (We have 82% of guards bw, 79% of midpoint bw, and 82% of exit bw = 54% of path bw.)
       Nov 25 01:13:14.000 [notice] Bootstrapped 71% (loading_descriptors): Loading relay descriptors
       Nov 25 01:13:15.000 [notice] Bootstrapped 75% (enough_dirinfo): Loaded enough directory info to build circuits
       Nov 25 01:13:15.000 [notice] Bootstrapped 80% (ap_conn): Connecting to a relay to build circuits
       Nov 25 01:13:15.000 [notice] Bootstrapped 85% (ap_conn_done): Connected to a relay to build circuits
       Nov 25 01:13:15.000 [notice] Bootstrapped 89% (ap_handshake): Finishing handshake with a relay to build circuits
       Nov 25 01:13:15.000 [notice] Bootstrapped 90% (ap_handshake_done): Handshake finished with a relay to build circuits
       Nov 25 01:13:15.000 [notice] Bootstrapped 95% (circuit_create): Establishing a Tor circuit
       Nov 25 01:13:15.000 [notice] Bootstrapped 100% (done): Done

   We can now stop Tor again using ctrl+c.

2. Tor should have created a new directory for us in our current working
   directory:

       $ ls -l onion-service-test
       total 16
       drwx------ 2 user user 4096 Nov 25 01:13 authorized_clients
       -rw------- 1 user user   63 Nov 25 01:13 hostname
       -rw------- 1 user user   64 Nov 25 01:13 hs_ed25519_public_key
       -rw------- 1 user user   96 Nov 25 01:13 hs_ed25519_secret_key

   These files are what makes up a Tor onion service. If we try to read the
   `hostname` file it will reveal the hostname of the newly generated onion
   service:

       $ cat onion-service-test/hostname 
       h35bxybaetjwnen332fvrvfyuixkpmpoppvermckng65aosadimpdpqd.onion

   Both `hs_ed25519_secret_key` and `hs_ed25519_public_key` are binary files,
   but let us take a look at the `hs_ed25519_public_key` using the hexdump
   utility:

       $ hexdump -C onion-service-test/hs_ed25519_public_key
       00000000  3d 3d 20 65 64 32 35 35  31 39 76 31 2d 70 75 62  |== ed25519v1-pub|
       00000010  6c 69 63 3a 20 74 79 70  65 30 20 3d 3d 00 00 00  |lic: type0 ==...|
       00000020  3e fa 1b e0 20 24 d3 66  91 bb de 8b 58 d4 b8 a2  |>... $.f....X...|
       00000030  2e a7 b1 ee 7b ea 48 b0  4a 69 bd d0 3a 40 1a 18  |....{.H.Ji..:@..|
       00000040

   The interesting part of this file is the last 32 bytes: `3e fa 1b e0 20 24
   d3 66 91 bb de 8b 58 d4 b8 a2 2e a7 b1 ee 7b ea 48 b0 4a 69 bd d0 3a 40 1a
   18`. This is the 32 byte ed25519 public key, which is also the value that is
   used to compute the onion service address found in the `hostname` file.

   The `hs_ed25519_secret_key` file contains the secret key, but we are not
   going to reveal that one in this document. This file should, as the name
   implies, remain secret.

3. We can now use the `onion-x509` tool to generate an x509 Certificate
   Authority using the files generated by Tor for our new onion service:

       $ onion-x509 ca create --secret-key onion-service-test/hs_ed25519_secret_key \
                              --output onion-ca.pem \
                              --organization "Test Onion CA" \
                              --country DK \
                              --locality Copenhagen
       2019/11/25 01:28:38 Loading ed25519 keys from onion-service-test/hs_ed25519_secret_key
       2019/11/25 01:28:38 Loaded ed25519 keys for h35bxybaetjwnen332fvrvfyuixkpmpoppvermckng65aosadimpdpqd.onion
       2019/11/25 01:28:38 Creating CA certificate
       2019/11/25 01:28:38 Saving Certificate Authority to onion-ca.pem

   The tool have now created the `onion-ca.pem` file for us, which contains the
   PEM-encoded CA certificate:

       $ cat onion-ca.pem
       -----BEGIN CERTIFICATE-----
       MIIBtzCCAWmgAwIBAgIRAKupDZqRM7jwJ2MKPw3W34kwBQYDK2VwMFsxCzAJBgNV
       BAYTAkRLMQkwBwYDVQQIEwAxEzARBgNVBAcTCkNvcGVuaGFnZW4xCTAHBgNVBAkT
       ADEJMAcGA1UEERMAMRYwFAYDVQQKEw1UZXN0IE9uaW9uIENBMB4XDTE5MTEyNTAx
       MjgzOFoXDTI5MTEyMjAxMjgzOFowWzELMAkGA1UEBhMCREsxCTAHBgNVBAgTADET
       MBEGA1UEBxMKQ29wZW5oYWdlbjEJMAcGA1UECRMAMQkwBwYDVQQREwAxFjAUBgNV
       BAoTDVRlc3QgT25pb24gQ0EwKjAFBgMrZXADIQA++hvgICTTZpG73otY1LiiLqex
       7nvqSLBKab3QOkAaGKNCMEAwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQGCCsG
       AQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAKeyrOuv
       FU09Ca8wrHf5Vxt+ePdaePm3galzfe8hKjgk4qtRgAAWM3JshPePEeCbF8/Ppmwu
       vHiMatXFzXLobQo=
       -----END CERTIFICATE-----

   Using the OpenSSL command-line tool we can inspect this certificate:

       $ openssl x509 -text -noout -in onion-ca.pem
       Certificate:
           Data:
               Version: 3 (0x2)
               Serial Number:
                   ab:a9:0d:9a:91:33:b8:f0:27:63:0a:3f:0d:d6:df:89
               Signature Algorithm: ED25519
               Issuer: C = DK, ST = , L = Copenhagen, street = , postalCode = , O = Test Onion CA
               Validity
                   Not Before: Nov 25 01:28:38 2019 GMT
                   Not After : Nov 22 01:28:38 2029 GMT
               Subject: C = DK, ST = , L = Copenhagen, street = , postalCode = , O = Test Onion CA
               Subject Public Key Info:
                   Public Key Algorithm: ED25519
                       ED25519 Public-Key:
                       pub:
                           3e:fa:1b:e0:20:24:d3:66:91:bb:de:8b:58:d4:b8:
                           a2:2e:a7:b1:ee:7b:ea:48:b0:4a:69:bd:d0:3a:40:
                           1a:18
               X509v3 extensions:
                   X509v3 Key Usage: critical
                       Digital Signature, Certificate Sign
                   X509v3 Extended Key Usage: 
                       TLS Web Client Authentication, TLS Web Server Authentication
                   X509v3 Basic Constraints: critical
                       CA:TRUE
           Signature Algorithm: ED25519
                a7:b2:ac:eb:af:15:4d:3d:09:af:30:ac:77:f9:57:1b:7e:78:
                f7:5a:78:f9:b7:81:a9:73:7d:ef:21:2a:38:24:e2:ab:51:80:
                00:16:33:72:6c:84:f7:8f:11:e0:9b:17:cf:cf:a6:6c:2e:bc:
                78:8c:6a:d5:c5:cd:72:e8:6d:0a

   If we take a look in the Subject Public Key Info section of the OpenSSL
   output, we can see that the public key used for this certificate is the same
   ed25519 public key as our onion service uses which we extracted with
   `hexdump` from the `hs_ed25519_public_key` file in the previous step.

4. Using our newly created Certificate Authority, we can now begin to create
   x509 certificates for our onion services:

       $ onion-x509 cert create --secret-key onion-service-test/hs_ed25519_secret_key \
                                --ca onion-ca.pem \
                                --output onion-cert.pem \
                                --hostnames "www.@, @" \
                                --organization "Test Certificate"
       2019/11/25 01:39:09 Loading ed25519 keys from onion-service-test/hs_ed25519_secret_key
       2019/11/25 01:39:09 Loaded ed25519 keys for h35bxybaetjwnen332fvrvfyuixkpmpoppvermckng65aosadimpdpqd.onion
       2019/11/25 01:39:09 Loading Certificate Authority from onion-ca.pem
       2019/11/25 01:39:09 Generating ed25519 keys for our certificate
       2019/11/25 01:39:09 Saving ed25519 secret key to onion-cert-secret-key.pem
       2019/11/25 01:39:09 Creating certificate
       2019/11/25 01:39:09 Saving certificate to onion-cert.pem

   The newly created `onion-cert.pem` and `onion-cert-secret-key.pem` are
   together with the `onion-ca.pem` file the files you have to use when setting up
   your TLS enabled services (for example to nginx for a webserver).

   We can take a look at the content of our newly created certificate:

       $ openssl x509 -text -noout -in onion-cert.pem
       Certificate:
           Data:
               Version: 3 (0x2)
               Serial Number:
                   94:12:ab:f1:ef:40:cf:6b:64:96:e6:be:10:c5:b5:0f
               Signature Algorithm: ED25519
               Issuer: C = DK, ST = , L = Copenhagen, street = , postalCode = , O = Test Onion CA
               Validity
                   Not Before: Nov 25 01:39:09 2019 GMT
                   Not After : Nov 24 01:39:09 2021 GMT
               Subject: C = , ST = , L = , street = , postalCode = , O = Test Certificate
               Subject Public Key Info:
                   Public Key Algorithm: ED25519
                       ED25519 Public-Key:
                       pub:
                           cd:78:ef:e0:78:ff:65:20:94:fa:2f:fc:63:b3:98:
                           6e:fe:b2:25:c7:9b:a9:c8:8a:6b:aa:87:ce:8f:d7:
                           d7:53
               X509v3 extensions:
                   X509v3 Key Usage: critical
                       Digital Signature
                   X509v3 Extended Key Usage: 
                       TLS Web Client Authentication, TLS Web Server Authentication
                   X509v3 Basic Constraints: critical
                       CA:FALSE
                   X509v3 Subject Alternative Name: 
                       DNS:www.h35bxybaetjwnen332fvrvfyuixkpmpoppvermckng65aosadimpdpqd.onion, DNS:h35bxybaetjwnen332fvrvfyuixkpmpoppvermckng65aosadimpdpqd.onion
           Signature Algorithm: ED25519
                78:8d:6a:80:40:5d:42:8d:b9:b6:e6:f4:46:af:5e:2f:f2:c3:
                d2:56:c7:50:32:a7:9c:39:2d:b8:c5:35:da:ff:52:99:c5:0b:
                9e:b1:8a:21:9b:68:f6:31:24:f5:ce:16:37:8d:dc:e6:ec:ae:
                0b:04:c3:f4:57:4c:c1:b1:01:07

   As we can see in this output, the "issuer" of our certificate is the "Test
   Onion CA" that we created in the previous step. We can also see that the @s
   used in the `--hostnames` parameter to our `onion-x509 cert` command have been
   expanded to the onion address of our onion service.

   We now have everything we need to setup an Onion service with TLS
   certificates that are signed using the identity key of the onion service.

## Test Site

One can have a look at
https://fxqcrxx5qj4aw7xllakk2qiux26dksiqjydyeb4gfq3f7wfs65yooaad.onion/ -- it
is setup using this tool, but do note that Tor Browser currently doesn't work
with it.

## Authors

- Alexander Færøy (<ahf@torproject.org>)
