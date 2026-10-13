(ns dk.simongray.webcrypto.fixtures
  "The keys and signatures that the tests of asymmetric keys share.

  They are the test vectors of Ed25519 in RFC 8032, the example keys and
  signatures of RFC 9421, and keys and signatures that the library made on
  the JVM and WebCrypto made in Node.")

;; RFC 8032, section 7.1
(def rfc-8032
  "The test vectors of Ed25519, in hex."
  [{:name      "TEST 1"
    :secret    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    :public    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    :message   ""
    :signature (str "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")}
   {:name      "TEST 2"
    :secret    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    :public    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    :message   "72"
    :signature (str "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")}
   {:name      "TEST 3"
    :secret    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
    :public    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    :message   "af82"
    :signature (str "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")}
   {:name      "TEST 1024"
    :secret    "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
    :public    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
    :message   (str "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
                    "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
                    "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
                    "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
                    "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
                    "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
                    "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
                    "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
                    "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
                    "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
                    "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
                    "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
                    "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
                    "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
                    "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
                    "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
                    "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
                    "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
                    "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
                    "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
                    "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
                    "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
                    "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
                    "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
                    "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
                    "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
                    "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
                    "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
                    "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
                    "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
                    "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
                    "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0")
    :signature (str "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
                    "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03")}
   {:name      "TEST SHA(abc)"
    :secret    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
    :public    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
    :message   (str "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    :signature (str "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
                    "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")}])

;; RFC 9421, Appendix B.1
(def rfc-9421
  "The example keys of RFC 9421 in PEM, as the RFC gives them."
  {:rsa-public
   (str "-----BEGIN RSA PUBLIC KEY-----\n"
        "MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw\n"
        "WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq\n"
        "MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg\n"
        "kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P\n"
        "uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ\n"
        "PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB\n"
        "-----END RSA PUBLIC KEY-----\n")
   :rsa-private
   (str "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP\n"
        "BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd\n"
        "JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75\n"
        "jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI\n"
        "lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ\n"
        "SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56\n"
        "vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE\n"
        "CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW\n"
        "+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA\n"
        "yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR\n"
        "Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J\n"
        "YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM\n"
        "cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw\n"
        "DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1\n"
        "mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT\n"
        "qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67\n"
        "B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv\n"
        "9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn\n"
        "f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo\n"
        "81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa\n"
        "/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG\n"
        "IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m\n"
        "qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P\n"
        "WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ\n"
        "EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=\n"
        "-----END RSA PRIVATE KEY-----\n")
   :rsa-pss-public
   (str "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2\n"
        "+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+\n"
        "oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq\n"
        "gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W\n"
        "Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4\n"
        "aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI\n"
        "2wIDAQAB\n"
        "-----END PUBLIC KEY-----\n")
   :rsa-pss-private
   (str "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv\n"
        "P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5\n"
        "3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr\n"
        "FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA\n"
        "AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw\n"
        "9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy\n"
        "c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq\n"
        "pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X\n"
        "aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4\n"
        "XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ\n"
        "HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD\n"
        "2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N\n"
        "RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx\n"
        "DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6\n"
        "vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm\n"
        "rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi\n"
        "4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL\n"
        "FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/\n"
        "OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx\n"
        "NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR\n"
        "NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ\n"
        "3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE\n"
        "t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND\n"
        "dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF\n"
        "S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR\n"
        "rOjr9w349JooGXhOxbu8nOxX\n"
        "-----END PRIVATE KEY-----\n")
   :ecc-p256-public
   (str "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf\n"
        "w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==\n"
        "-----END PUBLIC KEY-----\n")
   :ecc-p256-private
   (str "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49\n"
        "AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM\n"
        "4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==\n"
        "-----END EC PRIVATE KEY-----\n")
   :ed25519-public
   (str "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=\n"
        "-----END PUBLIC KEY-----\n")
   :ed25519-private
   (str "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n"
        "-----END PRIVATE KEY-----\n")})

;; RFC 9421, Appendix B.2, without the line wrapping of RFC 8792
(def rfc-9421-signatures
  "The examples of RFC 9421 that sign with the keys above: the keys, the
  algorithm of import-key and of sign, the signature base and the signature
  in base64. RSASSA-PKCS1-v1_5 and Ed25519 sign the same way each time."
  [{:name      "4.3"
    :public    :rsa-public
    :private   :rsa-private
    :algorithm {:name :rsassa-pkcs1-v1_5 :hash :sha-256}
    :signing   :rsassa-pkcs1-v1_5
    :base      (str "\"@method\": POST\n"
                    "\"@authority\": origin.host.internal.example\n"
                    "\"@path\": /foo\n"
                    "\"content-digest\": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T"
                    "aPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"
                    "\"content-type\": application/json\n"
                    "\"content-length\": 18\n"
                    "\"forwarded\": for=192.0.2.123;host=example.com;proto=https\n"
                    "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" "
                    "\"content-digest\" \"content-type\" \"content-length\" \"forwarded\")"
                    ";created=1618884480;keyid=\"test-key-rsa\";alg=\"rsa-v1_5-sha256\""
                    ";expires=1618884540")
    :signature (str "S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+JH+8XY1I6+8Cy"
                    "+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49GwiyUpZ10KHgOEe11s"
                    "x3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7LB5YAv0RAGhB8tmpv7sFn"
                    "Im9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtflzvZdXAsD3LH2TwevU+/PBPv0"
                    "B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbLVdp770I6VHR6WfgS9ddzirrswsE1w"
                    "5o0LV/g==")}
   {:name      "B.2.1"
    :public    :rsa-pss-public
    :private   :rsa-pss-private
    :algorithm {:name :rsa-pss :hash :sha-512}
    :signing   {:name :rsa-pss :salt-length 64}
    :base      (str "\"@signature-params\": ();created=1618884473;keyid=\"test-key-rsa-pss\""
                    ";nonce=\"b3k2pp5k7z-50gnwp.yemd\"")
    :signature (str "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx"
                    "31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNF"
                    "lD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWw"
                    "E56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH"
                    "1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw"
                    "9Q==")}
   {:name      "B.2.4"
    :public    :ecc-p256-public
    :private   :ecc-p256-private
    :algorithm {:name :ecdsa :named-curve :p-256}
    :signing   {:name :ecdsa :hash :sha-256}
    :base      (str "\"@status\": 200\n"
                    "\"content-type\": application/json\n"
                    "\"content-digest\": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJg"
                    "Jc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:\n"
                    "\"content-length\": 23\n"
                    "\"@signature-params\": (\"@status\" \"content-type\" \"content-digest\" "
                    "\"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"")
    :signature (str "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5e"
                    "CdlYUEkLIj+32oiasw==")}
   {:name      "B.2.6"
    :public    :ed25519-public
    :private   :ed25519-private
    :algorithm :ed25519
    :signing   :ed25519
    :base      (str "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n"
                    "\"@method\": POST\n"
                    "\"@path\": /foo\n"
                    "\"@authority\": example.com\n"
                    "\"content-type\": application/json\n"
                    "\"content-length\": 18\n"
                    "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" "
                    "\"content-type\" \"content-length\");created=1618884473"
                    ";keyid=\"test-key-ed25519\"")
    :signature (str "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w"
                    "6vuQv5lIp5WPpBKRCw==")}])

(def made-elsewhere
  "Key pairs that the library made on the JVM and WebCrypto made in Node,
  as the private key's JWK, the SPKI and PKCS#8 that the platform exported
  in hex, and the signature of its :message in hex. The algorithm is that
  of import-key, and :signing is that of sign."
  [{:made-on   :jvm
    :message   "Signed on the JVM, verified everywhere"
    :algorithm {:name :ecdsa :named-curve :p-384}
    :signing   {:name :ecdsa :hash :sha-384}
    :jwk       {:kty "EC"
                :crv "P-384"
                :x   "nd2zDdoVHtfKE6m-YueMDJexBHwOaCcGNSuhW_6h70xeMlmMUb-U5IMnCVROAx9w"
                :y   "NO953BC-vjHugrCCqSnvkGkz9qa0FFLnJ0DQiSDpX4vKGMTjHY749m-sKjj4RC43"
                :d   "pD4PvdUVIC1t2L1EMGutwRKpTtZQctmCckeGQxNC1KqV_O-8nj3U-1Ty4oXbchta"}
    :spki      (str "3076301006072a8648ce3d020106052b81040022036200049dddb30dda151ed7"
                    "ca13a9be62e78c0c97b1047c0e682706352ba15bfea1ef4c5e32598c51bf94e4"
                    "832709544e031f7034ef79dc10bebe31ee82b082a929ef906933f6a6b41452e7"
                    "2740d08920e95f8bca18c4e31d8ef8f66fac2a38f8442e37")
    :pkcs8     (str "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201"
                    "010430a43e0fbdd515202d6dd8bd44306badc112a94ed65072d9827247864313"
                    "42d4aa95fcefbc9e3dd4fb54f2e285db721b5aa164036200049dddb30dda151e"
                    "d7ca13a9be62e78c0c97b1047c0e682706352ba15bfea1ef4c5e32598c51bf94"
                    "e4832709544e031f7034ef79dc10bebe31ee82b082a929ef906933f6a6b41452"
                    "e72740d08920e95f8bca18c4e31d8ef8f66fac2a38f8442e37")
    :signature (str "10a1b0b5a424704d412faf506bc3a6e3458f7e798bf887daa240be12d48828a2"
                    "c49cc1273450af2a33d4d2c6ed2768652f2baea0f7af96e39611ec32a5b49e32"
                    "a96252faa0151af1f2f4c9bf7081907f406311d90164b3f96c72a4154aec76dc")}
   {:made-on   :jvm
    :message   "Signed on the JVM, verified everywhere"
    :algorithm {:name :rsa-pss :hash :sha-256}
    :signing   {:name :rsa-pss :salt-length 32}
    :jwk       {:kty "RSA"
                :alg "PS256"
                :n   (str "xMXfvstzkjeOwlPsWmb6jgzo8IjA3TygLDBZ9VPj37_spVyIpGIFwfqTPsE2HKKL"
                          "b2S9dsGLUhmKcssgTlVKncKyMnCYla9c6midLaSbh6y_HNbajbUOtqHaaCB1Kfy7"
                          "-wixeghDNZVxw4hiX-Uf6BZBynXSOelyf1MU89a2qTYgJ-_TrnV1ocE-YOfLp88A"
                          "QP779xSaOVRCgzFTQdJYnaiJYKMi3tcIRfG30mH0QvgulkKvQA-xdenvSDkVzvSv"
                          "BT0JmQ0h-p7rzjPAtusJYCGZPXUdXD6EDhG7xZ0bQsQl3EuQdd33h4q62WAfBjJa"
                          "mCx3KWM25LMn8cX7zTXqkw")
                :e   "AQAB"
                :d   (str "D0qlUalz6MgCgx2Mf5YDIKjmLVMjUc4VUHnNc-A6FDhRBqTDRasMcX-sk7LmJqGH"
                          "HngAtUrjLdUoSjV45D2Cl_H6cSsI4JEJMnpAxLxHDeshyvbzcxG_-_dmBrOHB2VJ"
                          "on-Rcz9TIcXkWmKt6m_e4-Ve5YH0fWWj7TsipLRp64pTXktbsxZIEW1qlycZGtF7"
                          "8N9flQyzp8llpJcvn9RLPivcla5mAzaNv4QHnZHJ0z_ZwBd2Hq7A-cKNEaX9_sb8"
                          "gCDRUiEQRfOjW4UeF7w7qvYrRNc-C04XjG1n4TMpIibqV2OGN-aRfzmLsqUAY-_J"
                          "7sXZEQ_fcTkNyBcxoWhemQ")
                :p   (str "5iJZ77ZUcDs26Kg13VYE1A9WRHZrv4W03FTnmATJ06S7k2c7_TroViXyjqqCu4Pa"
                          "pr9s2xxYgRdosL-2fARrHA0OxaY7J5H69iQhDbE_IjRu6AlEG5bcUYv63IwBzEAh"
                          "VsISg4HFFRJkETkZ5JNBFPS-jI0T3EVFXh60Hr7TsrU")
                :q   (str "2uOevMpWpWita0Gu2hEeh47VrmIiaPo-EHq_8ay585UYDN4o_ApYGoWk0-0kXdcb"
                          "q7s6plc-Xm-4JG-GfTOxXr0As-Q5WmoNZnOC9e6vGYbJWaRBwD-FVwZWyzBn-KOh"
                          "7gAKoBu3gEzi9Z4HCxo3MoJqjoeNtSU1pF6oOGhojSc")
                :dp  (str "cM6z4UIx_9W247LYvIdW1JA0DFk0Fey3rC1eXPEz8a_VVrsK9-VxUBFH5dEFRl-q"
                          "xYQeGwW5CIZuBf3juMT9sAFilVYXtxzitNce8LRKqzyihNFN9mwr0TlZndRvaSyi"
                          "awG0y4vIDL04Gg0weRAJnfkekozxCE9YYnuQdWW7JeU")
                :dq  (str "QYGPNtai-ZuLEqc0icRHy6--WRK7U4lYW5wwp0XW3IPJD8jIoS0DUuSeAGJe2MqQ"
                          "WGOO2MsROjfa9uR9biizMzQC6tMpKtrEKd312l3U_yGsTmxu1Pbtk66s-OACrZFi"
                          "25Qdme7Ris73uSPS3cq5rB8FfqQoj4aUOB2v4Dm22E8")
                :qi  (str "eNIvbKj57ic5ifdHG_wXtyO_Mwlf903dDpldBJYlZtqcucX5gBUMCUxUeGOozbWR"
                          "pkpdOY1xLLh-QPUXGYxcHmw5COn_ffKn6IBAgmdRJamTUvLeYtT5aBDwR4VRW0WP"
                          "8MF8-L-1Ve1NQEgNXVC4_aLu2rfx8Ub9waNigDco-j8")}
    :spki      (str "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
                    "00c4c5dfbecb7392378ec253ec5a66fa8e0ce8f088c0dd3ca02c3059f553e3df"
                    "bfeca55c88a46205c1fa933ec1361ca28b6f64bd76c18b52198a72cb204e554a"
                    "9dc2b232709895af5cea689d2da49b87acbf1cd6da8db50eb6a1da68207529fc"
                    "bbfb08b17a0843359571c388625fe51fe81641ca75d239e9727f5314f3d6b6a9"
                    "362027efd3ae7575a1c13e60e7cba7cf0040fefbf7149a39544283315341d258"
                    "9da88960a322ded70845f1b7d261f442f82e9642af400fb175e9ef483915cef4"
                    "af053d09990d21fa9eebce33c0b6eb096021993d751d5c3e840e11bbc59d1b42"
                    "c425dc4b9075ddf7878abad9601f06325a982c77296336e4b327f1c5fbcd35ea"
                    "930203010001")
    :pkcs8     (str "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201"
                    "000282010100c4c5dfbecb7392378ec253ec5a66fa8e0ce8f088c0dd3ca02c30"
                    "59f553e3dfbfeca55c88a46205c1fa933ec1361ca28b6f64bd76c18b52198a72"
                    "cb204e554a9dc2b232709895af5cea689d2da49b87acbf1cd6da8db50eb6a1da"
                    "68207529fcbbfb08b17a0843359571c388625fe51fe81641ca75d239e9727f53"
                    "14f3d6b6a9362027efd3ae7575a1c13e60e7cba7cf0040fefbf7149a39544283"
                    "315341d2589da88960a322ded70845f1b7d261f442f82e9642af400fb175e9ef"
                    "483915cef4af053d09990d21fa9eebce33c0b6eb096021993d751d5c3e840e11"
                    "bbc59d1b42c425dc4b9075ddf7878abad9601f06325a982c77296336e4b327f1"
                    "c5fbcd35ea930203010001028201000f4aa551a973e8c802831d8c7f960320a8"
                    "e62d532351ce155079cd73e03a14385106a4c345ab0c717fac93b2e626a1871e"
                    "7800b54ae32dd5284a3578e43d8297f1fa712b08e09109327a40c4bc470deb21"
                    "caf6f37311bffbf76606b387076549a27f91733f5321c5e45a62adea6fdee3e5"
                    "5ee581f47d65a3ed3b22a4b469eb8a535e4b5bb31648116d6a9727191ad17bf0"
                    "df5f950cb3a7c965a4972f9fd44b3e2bdc95ae6603368dbf84079d91c9d33fd9"
                    "c017761eaec0f9c28d11a5fdfec6fc8020d152211045f3a35b851e17bc3baaf6"
                    "2b44d73e0b4e178c6d67e133292226ea57638637e6917f398bb2a50063efc9ee"
                    "c5d9110fdf71390dc81731a1685e9902818100e62259efb654703b36e8a835dd"
                    "5604d40f5644766bbf85b4dc54e79804c9d3a4bb93673bfd3ae85625f28eaa82"
                    "bb83daa6bf6cdb1c58811768b0bfb67c046b1c0d0ec5a63b2791faf624210db1"
                    "3f22346ee809441b96dc518bfadc8c01cc402156c2128381c5151264113919e4"
                    "934114f4be8c8d13dc45455e1eb41ebed3b2b502818100dae39ebcca56a568ad"
                    "6b41aeda111e878ed5ae622268fa3e107abff1acb9f395180cde28fc0a581a85"
                    "a4d3ed245dd71babbb3aa6573e5e6fb8246f867d33b15ebd00b3e4395a6a0d66"
                    "7382f5eeaf1986c959a441c03f85570656cb3067f8a3a1ee000aa01bb7804ce2"
                    "f59e070b1a3732826a8e878db52535a45ea83868688d2702818070ceb3e14231"
                    "ffd5b6e3b2d8bc8756d490340c593415ecb7ac2d5e5cf133f1afd556bb0af7e5"
                    "71501147e5d105465faac5841e1b05b908866e05fde3b8c4fdb00162955617b7"
                    "1ce2b4d71ef0b44aab3ca284d14df66c2bd139599dd46f692ca26b01b4cb8bc8"
                    "0cbd381a0d307910099df91e928cf1084f58627b907565bb25e502818041818f"
                    "36d6a2f99b8b12a73489c447cbafbe5912bb5389585b9c30a745d6dc83c90fc8"
                    "c8a12d0352e49e00625ed8ca9058638ed8cb113a37daf6e47d6e28b3333402ea"
                    "d3292adac429ddf5da5dd4ff21ac4e6c6ed4f6ed93aeacf8e002ad9162db941d"
                    "99eed18acef7b923d2ddcab9ac1f057ea4288f8694381dafe039b6d84f028180"
                    "78d22f6ca8f9ee273989f7471bfc17b723bf33095ff74ddd0e995d04962566da"
                    "9cb9c5f980150c094c547863a8cdb591a64a5d398d712cb87e40f517198c5c1e"
                    "6c3908e9ff7df2a7e8804082675125a99352f2de62d4f96810f04785515b458f"
                    "f0c17cf8bfb555ed4d40480d5d50b8fda2eedab7f1f146fdc1a362803728fa3f")
    :signature (str "134fe9ef31f484f15837dc432e3a45401518bb99957f1f2b7d8f5d3b114ef477"
                    "e8939db56638b2ee6e2abf52d534f1b187d6848ab7f6953c95f0d9da0d37a5ab"
                    "b5077e071d054aedf68ea7db1f8f717e6c13d2acfbae07a6900dfe5be25e2362"
                    "78106caf569769c6a0b7cc70814b1e72b2468f2535fdec52598096b606198a70"
                    "12e72154efb9c3d1597a744bc92af2b47ae2fb2e5a672eea6f54a9ff13db2a2d"
                    "887815bf458cce2227e2724cadf40d23566a33f6d49d895cb5049cf2c61f4183"
                    "ac49f104396172433a82d4af031c766ffa3a2c624bb3405fd9c5ae9fd87e76b0"
                    "04e204c82016a99354c8cc78ff7ef196d1410492bb6fdc269ec32b7b459ec587")}
   {:made-on   :jvm
    :message   "Signed on the JVM, verified everywhere"
    :algorithm :ed25519
    :signing   :ed25519
    :jwk       {:kty "OKP"
                :crv "Ed25519"
                :alg "Ed25519"
                :x   "8z4RH3P2b4fMbvqz2SCZue8Pm61rPtFXy1M633_YyD8"
                :d   "aaAKJkzAHa9dI8p4N5mJUe7n8iIpScVJFKgTx4OvRgk"}
    :spki      (str "302a300506032b6570032100f33e111f73f66f87cc6efab3d92099b9ef0f9bad"
                    "6b3ed157cb533adf7fd8c83f")
    :pkcs8     (str "302e020100300506032b65700422042069a00a264cc01daf5d23ca7837998951"
                    "eee7f2222949c54914a813c783af4609")
    :signature (str "949091cb350a60b7f0195d19dd239fc976bff2751494cf7d885efea7f3c02414"
                    "750e074644cb86951d393fac3e36ec4b4d688fd691fc58ea43658fa24ae4ac0f")}
   {:made-on   :jvm
    :algorithm {:name :ecdh :named-curve :p-256}
    :jwk       {:kty "EC"
                :crv "P-256"
                :x   "KPz3n7mu-DFRhmg8YCD7v-NVS1sW-875Hd2Q1kodZFw"
                :y   "leAgQLiHornoARKMk9sqHqV_ybsAd1-RflepEXTn8P8"
                :d   "d0U8WPj8esJepEAzP2frJiqBuuV7z4ztj4qGILHON78"}
    :spki      (str "3059301306072a8648ce3d020106082a8648ce3d0301070342000428fcf79fb9"
                    "aef8315186683c6020fbbfe3554b5b16fbcef91ddd90d64a1d645c95e02040b8"
                    "87a2b9e801128c93db2a1ea57fc9bb00775f917e57a91174e7f0ff")
    :pkcs8     (str "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
                    "0101042077453c58f8fc7ac25ea440333f67eb262a81bae57bcf8ced8f8a8620"
                    "b1ce37bfa1440342000428fcf79fb9aef8315186683c6020fbbfe3554b5b16fb"
                    "cef91ddd90d64a1d645c95e02040b887a2b9e801128c93db2a1ea57fc9bb0077"
                    "5f917e57a91174e7f0ff")}
   {:made-on   :node
    :message   "Signed in Node, verified everywhere"
    :algorithm {:name :ecdsa :named-curve :p-256}
    :signing   {:name :ecdsa :hash :sha-256}
    :jwk       {:kty "EC"
                :crv "P-256"
                :x   "9yamYZvVxnAKy9frxJaahw7EPGloQ-y1a_ZZy7CTrIg"
                :y   "QIQr5iAp_VDEgeIQSVgD5UxHYdKWXEbVcKToUXPDOfQ"
                :d   "vtQe3PKvDohDz2vGfxPHoHS6a8Qa9frYaSVMpz64bd0"}
    :spki      (str "3059301306072a8648ce3d020106082a8648ce3d03010703420004f726a6619b"
                    "d5c6700acbd7ebc4969a870ec43c696843ecb56bf659cbb093ac8840842be620"
                    "29fd50c481e210495803e54c4761d2965c46d570a4e85173c339f4")
    :pkcs8     (str "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
                    "01010420bed41edcf2af0e8843cf6bc67f13c7a074ba6bc41af5fad869254ca7"
                    "3eb86ddda14403420004f726a6619bd5c6700acbd7ebc4969a870ec43c696843"
                    "ecb56bf659cbb093ac8840842be62029fd50c481e210495803e54c4761d2965c"
                    "46d570a4e85173c339f4")
    :signature (str "9b86fde6c5268e319d95ca86731fdc894014c0a98b1a12c1e101522da4385a30"
                    "2300da23f7499a308186a54aaff79177860e1f0f7cd6c5c4daa232c0d9d90996")}
   {:made-on   :node
    :message   "Signed in Node, verified everywhere"
    :algorithm {:name :rsassa-pkcs1-v1_5 :hash :sha-256}
    :signing   :rsassa-pkcs1-v1_5
    :jwk       {:kty "RSA"
                :alg "RS256"
                :n   (str "uvw2zD4wXlwUME07y01fx_V1fEdtFscQVqscuoj8Qeo10OLkJtPgqg-SKwAasDv1"
                          "927aZf7_QmPIP8B6WfXbE1vwnnytn7lbgmd0fPuNAFD2n5F1I2Pqys2_KZXl2G-k"
                          "bSe4WbiJSTF8K0h7KARrpVppTDls3Yad7iL__6d5dlFWS22JRVYdbRBHycMFXuhs"
                          "bXEJpC462KEhOq9lrsMiH0Oh2Rucx03Jqj5heBGJikFv06JWhbmb4eaNhhDm7C-D"
                          "KhBgexJi2cZpA3JOt6UPJ2pITAAsVgE_MbmcZm8MWndgDOso4QlbC0Jd_gqKTX3R"
                          "xVklozng-GiS5iP9olM7Zw")
                :e   "AQAB"
                :d   (str "C3g1FEosRV14j43tQQc5_NX9ouXutxr20ZolZPvKHXD0ZB_GxurwOP5DhQe4m17S"
                          "M59FHkSJ-9SLD_4Kg0IlcgaNt-sF62o_Rrx51MDJYV-WASu297jFSjNcqnxbYO9Y"
                          "MqnhEP_Uy_yRFUaY51d-EuJ82wQavWvofBcBhPkM5kj0FwliYmbIAgy7FVBbGGTu"
                          "HNtkMI3-Souysh0y32q7tL9Ipc6XRusLiJm93Dc-VHNac_2K73RP5ovBA1MTs23L"
                          "x-UmYJazyBJnEnJvzoeGdcoyXBSQyiliWUGG1uDCySsFYrRdqz1qmgPSPVMe39vR"
                          "MC6rR9WfrtVeFLQ4E6dfoQ")
                :p   (str "5XWOG4sKo-aTzaCbYCNR9nYkX1Tm-6IZaTlATcTSWC35VWMSkQV2vLO09TgsmH1l"
                          "9-Wq-IBqO3elS95w6dj-HiZ9ij-MMg5233NltxW55Dcl-rqbRF-FFDLJVP-kVUh_"
                          "2oo-tiK9QILbgJ77UJQ2Uldi6ZWWCDXPc5Erzcx-HDU")
                :q   (str "0Jz5ky-mQjJhJjm_b7FFCx8yG2lgSJqCzMcbvCxSZ6a4QGtio_zJ50k93fzUu1KL"
                          "jeC4hKz3yrVr0uhR2YIoh4yOndPIJCLMJy8oNsZjFLGP8nxSAD4t7zjE-CfmX9S3"
                          "rWSBHvamagstR8YjFNp6HyScGHykpEHk-P20464hVKs")
                :dp  (str "yzezpd0cjVAWstR9B0YAvyCe0fdlopJLow9bTgT0rbf5zI-zz9Bg-nrF1y_q_xqA"
                          "Bm7XXsKMUyKBuJHGurS9SoKYSKpDRcndqcSP3vhU7DOTZV2DSai3Oc5I1QibyBQv"
                          "d6NcKv7VUZ8TO_SRayn4ejB-n5UljRvrINT_UIK9Zck")
                :dq  (str "er-C0qo858KBC177V5s1BwBKGXr9nnrb7-ZQWX6y1i5xR-Zn2hoKKz8bWh1Ehxxg"
                          "5RCPQfIMs4fgc-8jChreAjQgTpmosCqReZTz0pcVAb4g9wtTrLTpjlMXAvVnRogB"
                          "s9LpbvCupsMA17SsO776EI0YFAhzT_s94YxW_YkeL5U")
                :qi  (str "CSBIr0O1DukuezVtUG638FeSLFvKzn7P7bbTM17KrIaNtS9HjgA3aH3HNDLkSwPt"
                          "SpzMi5JUCTXuW7wlXrmOBNbWMvQdh688u5ceYokk8nt5Hyn00X--uA0QLKYsGJnm"
                          "tP5dMtMnsffHgtN78Yj0gCohFx_Hqg67o0xYjPbtVCw")}
    :spki      (str "30820122300d06092a864886f70d01010105000382010f003082010a02820101"
                    "00bafc36cc3e305e5c14304d3bcb4d5fc7f5757c476d16c71056ab1cba88fc41"
                    "ea35d0e2e426d3e0aa0f922b001ab03bf5f76eda65feff4263c83fc07a59f5db"
                    "135bf09e7cad9fb95b8267747cfb8d0050f69f91752363eacacdbf2995e5d86f"
                    "a46d27b859b88949317c2b487b28046ba55a694c396cdd869dee22ffffa77976"
                    "51564b6d8945561d6d1047c9c3055ee86c6d7109a42e3ad8a1213aaf65aec322"
                    "1f43a1d91b9cc74dc9aa3e617811898a416fd3a25685b99be1e68d8610e6ec2f"
                    "832a10607b1262d9c66903724eb7a50f276a484c002c56013f31b99c666f0c5a"
                    "77600ceb28e1095b0b425dfe0a8a4d7dd1c55925a339e0f86892e623fda2533b"
                    "670203010001")
    :pkcs8     (str "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201"
                    "000282010100bafc36cc3e305e5c14304d3bcb4d5fc7f5757c476d16c71056ab"
                    "1cba88fc41ea35d0e2e426d3e0aa0f922b001ab03bf5f76eda65feff4263c83f"
                    "c07a59f5db135bf09e7cad9fb95b8267747cfb8d0050f69f91752363eacacdbf"
                    "2995e5d86fa46d27b859b88949317c2b487b28046ba55a694c396cdd869dee22"
                    "ffffa7797651564b6d8945561d6d1047c9c3055ee86c6d7109a42e3ad8a1213a"
                    "af65aec3221f43a1d91b9cc74dc9aa3e617811898a416fd3a25685b99be1e68d"
                    "8610e6ec2f832a10607b1262d9c66903724eb7a50f276a484c002c56013f31b9"
                    "9c666f0c5a77600ceb28e1095b0b425dfe0a8a4d7dd1c55925a339e0f86892e6"
                    "23fda2533b670203010001028201000b7835144a2c455d788f8ded410739fcd5"
                    "fda2e5eeb71af6d19a2564fbca1d70f4641fc6c6eaf038fe438507b89b5ed233"
                    "9f451e4489fbd48b0ffe0a83422572068db7eb05eb6a3f46bc79d4c0c9615f96"
                    "012bb6f7b8c54a335caa7c5b60ef5832a9e110ffd4cbfc91154698e7577e12e2"
                    "7cdb041abd6be87c170184f90ce648f41709626266c8020cbb15505b1864ee1c"
                    "db64308dfe4a8bb2b21d32df6abbb4bf48a5ce9746eb0b8899bddc373e54735a"
                    "73fd8aef744fe68bc1035313b36dcbc7e5266096b3c8126712726fce878675ca"
                    "325c1490ca2962594186d6e0c2c92b0562b45dab3d6a9a03d23d531edfdbd130"
                    "2eab47d59faed55e14b43813a75fa102818100e5758e1b8b0aa3e693cda09b60"
                    "2351f676245f54e6fba2196939404dc4d2582df9556312910576bcb3b4f5382c"
                    "987d65f7e5aaf8806a3b77a54bde70e9d8fe1e267d8a3f8c320e76df7365b715"
                    "b9e43725faba9b445f851432c954ffa455487fda8a3eb622bd4082db809efb50"
                    "9436525762e995960835cf73912bcdcc7e1c3502818100d09cf9932fa6423261"
                    "2639bf6fb1450b1f321b6960489a82ccc71bbc2c5267a6b8406b62a3fcc9e749"
                    "3dddfcd4bb528b8de0b884acf7cab56bd2e851d98228878c8e9dd3c82422cc27"
                    "2f2836c66314b18ff27c52003e2def38c4f827e65fd4b7ad64811ef6a66a0b2d"
                    "47c62314da7a1f249c187ca4a441e4f8fdb4e3ae2154ab02818100cb37b3a5dd"
                    "1c8d5016b2d47d074600bf209ed1f765a2924ba30f5b4e04f4adb7f9cc8fb3cf"
                    "d060fa7ac5d72feaff1a80066ed75ec28c532281b891c6bab4bd4a829848aa43"
                    "45c9dda9c48fdef854ec3393655d8349a8b739ce48d5089bc8142f77a35c2afe"
                    "d5519f133bf4916b29f87a307e9f95258d1beb20d4ff5082bd65c90281807abf"
                    "82d2aa3ce7c2810b5efb579b3507004a197afd9e7adbefe650597eb2d62e7147"
                    "e667da1a0a2b3f1b5a1d44871c60e5108f41f20cb387e073ef230a1ade023420"
                    "4e99a8b02a917994f3d2971501be20f70b53acb4e98e531702f567468801b3d2"
                    "e96ef0aea6c300d7b4ac3bbefa108d181408734ffb3de18c56fd891e2f950281"
                    "80092048af43b50ee92e7b356d506eb7f057922c5bcace7ecfedb6d3335ecaac"
                    "868db52f478e0037687dc73432e44b03ed4a9ccc8b92540935ee5bbc255eb98e"
                    "04d6d632f41d87af3cbb971e628924f27b791f29f4d17fbeb80d102ca62c1899"
                    "e6b4fe5d32d327b1f7c782d37bf188f4802a21171fc7aa0ebba34c588cf6ed54"
                    "2c")
    :signature (str "19ad8e7a88805c641516c4b65430d2ceff739b13f475d657c79d55ff7a02fa02"
                    "f49fbb7b66f2c72c6fa2a0e7c2f8ea2a069f8766e3d2bda58fd6a2de3169ba57"
                    "9ad5545d1b9172f76a15eb011eafb8ced9252b7734b896cb98712c628fa0327c"
                    "150d8dfd822dba8d662b2feefb0580edf7127b27b3789ee4b2eca9a52b96e0e1"
                    "662694427d259d81bd2e1cf0698166ce61aeccf325e719872555e42f8e46f9c4"
                    "0b8f8e646fbd868ae613ef33f6744c0291e24290d3369c9ea258dbde6731ac64"
                    "791b91d802bf5ce2dcd278f194bf2f5474f26c8bed57cf124363dc2e6c1879dc"
                    "36441594bf07966175051d37ca50db10c7e59d800cf939f0db36d5f7e5f9300c")}
   {:made-on   :node
    :message   "Signed in Node, verified everywhere"
    :algorithm :ed25519
    :signing   :ed25519
    :jwk       {:kty "OKP"
                :crv "Ed25519"
                :alg "Ed25519"
                :x   "_RwHE7bumbqBsvfE8Al9JYu_bVmdwUI2wuzs-3o6K9E"
                :d   "Jt0_h12xYGDpQqaYsDEffRwDiU6kRf63AyE8qtvhc5k"}
    :spki      (str "302a300506032b6570032100fd1c0713b6ee99ba81b2f7c4f0097d258bbf6d59"
                    "9dc14236c2ececfb7a3a2bd1")
    :pkcs8     (str "302e020100300506032b65700422042026dd3f875db16060e942a698b0311f7d"
                    "1c03894ea445feb703213caadbe17399")
    :signature (str "6dab9b340ab058b86df683d81a399ed4f7a375f2ac8c3be16392d0e694a4898a"
                    "892b9b59c7ef78365198cc29cfa7342fe433bc772d83e647e63acb9c76c4580b")}
   {:made-on   :node
    :algorithm {:name :ecdh :named-curve :p-256}
    :jwk       {:kty "EC"
                :crv "P-256"
                :x   "NFY4rz6fbPoypXpSXibSQqyG9ue-_5ZeTMpCN-9OKMQ"
                :y   "zOA9-_OdKZ1I6kp8QLVnoxBNLtsUyAqjn6gP0cCILOc"
                :d   "ut2wa1R1GPw-xO2Cyhs8tvBMyYZnb6QUsU8xY5LczaI"}
    :spki      (str "3059301306072a8648ce3d020106082a8648ce3d03010703420004345638af3e"
                    "9f6cfa32a57a525e26d242ac86f6e7beff965e4cca4237ef4e28c4cce03dfbf3"
                    "9d299d48ea4a7c40b567a3104d2edb14c80aa39fa80fd1c0882ce7")
    :pkcs8     (str "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
                    "01010420baddb06b547518fc3ec4ed82ca1b3cb6f04cc986676fa414b14f3163"
                    "92dccda2a14403420004345638af3e9f6cfa32a57a525e26d242ac86f6e7beff"
                    "965e4cca4237ef4e28c4cce03dfbf39d299d48ea4a7c40b567a3104d2edb14c8"
                    "0aa39fa80fd1c0882ce7")}])
