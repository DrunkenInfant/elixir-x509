defmodule X509.JWKTest do
  use ExUnit.Case

  test "from certificate" do
    assert %{
             "kty" => "RSA",
             "n" =>
               "55XP15-x92Wm56FIyKnqvkrqq9qo4Eko4P13UEyTS_RSs70Ubm7CBBgPZ3LMnp8aav-McIVLFTIjHlDBolfh8fp8UCpLeyT1_Rsuj37LP6J531UKUALM8Zyr6u_0hGXhW1-yCwwTPKtfdRJi66u8ZmIaldviNWiKJ0IwpFF2zWwLjyVI2KfMhLdx7qimTd5y-7ADCouLuVC9Nk2wbS3yP6LRPyrrh9d1xv8kHyX7g9MYN2Ziv9DIJRM7rFIl9IoEMnfUqPhNN4JsEieOWUy3uOlwiDNk-H2T5qHs4CkiE85yUIbs9wNuTu1wpHp5cjeH6h8NCr7k-x_PowzhO6nh3w",
             "e" => "AQAB",
             "alg" => "RS256",
             "kid" => "first_issuer/A8Gi0H9Y2nexEOqA6uK7k0_6CRw",
             "use" => "sig",
             "x5c" => [
               "MIIDuDCCAqCgAwIBAgIUA8Gi0H9Y2nexEOqA6uK7k0/6CRwwDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UEAwwMZmlyc3RfaXNzdWVyMB4XDTE5MDUyNDE0MDMyN1oXDTE5MDUyNDE0MDg1N1owFTETMBEGA1UEAwwKZmlyc3RfY2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOeVz9efsfdlpuehSMip6r5K6qvaqOBJKOD9d1BMk0v0UrO9FG5uwgQYD2dyzJ6fGmr/jHCFSxUyIx5QwaJX4fH6fFAqS3sk9f0bLo9+yz+ied9VClACzPGcq+rv9IRl4VtfsgsMEzyrX3USYuurvGZiGpXb4jVoiidCMKRRds1sC48lSNinzIS3ce6opk3ecvuwAwqLi7lQvTZNsG0t8j+i0T8q64fXdcb/JB8l+4PTGDdmYr/QyCUTO6xSJfSKBDJ31Kj4TTeCbBInjllMt7jpcIgzZPh9k+ah7OApIhPOclCG7PcDbk7tcKR6eXI3h+ofDQq+5Psfz6MM4Tup4d8CAwEAAaOB/TCB+jAOBgNVHQ8BAf8EBAMCA6gwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFMi5rj8SFOSP39BdLaTl9Joj0Wv3MB8GA1UdIwQYMBaAFAnu268sbCXPMhbUPCrtpDtDqQNLMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL2xvY2FsaG9zdDo4MjAxL2ZpcnN0X2lzc3Vlci9PcVhxdnVHZ3MtcC10czVxdjBObWliMVdMd28wNwYDVR0fBDAwLjAsoCqgKIYmaHR0cDovL2xvY2FsaG9zdDo4MjAxL2ZpcnN0X2lzc3Vlci9jcmwwDQYJKoZIhvcNAQELBQADggEBAKBXjiq4xFF0xoK3Z/1oT78RMBHVByg/2bYHp4DSyz12w3DM3tikjGUSGMkHZOBtWds5MhScfnlX5uZzDmxfxbmJ2YwcFksMMl0DK6FAWthF2IzrJrYpVFBdvOK8ShtfwgZIqd9Y0q+pxy/whkUC5/v+heSKnvr/bJySk66/0cuykbUQOKP1r7lnirpQEIWN+gmJLPGrIAWwdT5WmXe/eTkvVjFfzhu3dItdyy07e3BezSHxcxIK7HnAjrA5wqTfoqGo6C7vZgti28zMy36IWtlWiVzG9kqt5hGw6Y9qsSCZ/tBeuc6E7uxN6tnrhdyIF7/YAxUzD6noO9jJvzdyKko="
             ],
             "x5t" => "2jowrE8PE3RbZlR1rJoYwDWx5B0=",
             "x5t#S256" => "2+M4K4uxVNNjLY0f4T1TKF2yc/rzmu1UJpKAhbWiXJQ="
           } ==
             X509.CertificateHelper.x509_public()
             |> X509.Certificate.from_pem()
             |> X509.JWK.to_jwk()
  end
end
