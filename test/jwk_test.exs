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

  test "from rsa private key" do
    assert %{
             "d" =>
               "oCJ2jgRa0vvYMYXowFYDfQu_J82_9btquHSFeHOrwRe7PBFquXpuR6mntXPw2esXXvPZfCQUZmTL3PbPmJB1bdrWrNfSbV-bSCljdu6gvfEnZytNkBkObr4BastjYDlL8IHlOCKun2TYLTlKDdhrScmyPXdDQx32s1lay9yACuxt4XWTsOUBD3cU1gjX3bv9hrTv8UdIngCmSLMaz7Zy1ZgFbfdKqODfDhFxkTiJXOMDI8WGbgG9IGBcHbPLuXVA0QHOQMy5giCuDw55yCocYIGrVrJH7kItBxKnspm97kRZPQYmL6Vq13R1_KffKVT6a7GMX_vN9QMkzHz7KiX9yQ",
             "dp" =>
               "Yog6YfRcZcrKTdvg14GUEQXUv9BAaApSPO9NZevbQB-Cd3RzPEexHpXU1-cdFr1Z2WJncI2Oz77vWDkPaMY6xyeZWtnXOpXDBEv-VROZjojPCnU5ZEiXM2cqU1_XrW0sQXHZriESLdMnCRON2SvmCeEW6IxEGrGItxB6zjs0JAE",
             "dq" =>
               "sIGVpejXZdbH-OXyjRio7PE2Zb2usbj0Ck-M_PtYWKJ6gWdoYTPMK6FGwF90MVaonx4JnXExEqYk1184HBFhfXd7AGsw4GPE3eTqMfjGkd0IMaAP-Sgp2sBBv1WlDpi8OL2gaGAkxum8Mr3_Aa4vikAI4WYdq0xIJy3CqGpILo8",
             "e" => "AQAB",
             "kty" => "RSA",
             "n" =>
               "v-Q-7ncTQjHnPqdQN32EF_smzohLsjhea98Et9mjA5Gu9Hb7PAJW27C9s3dxR8ox73kU2AAKPArGyPFA1z6A1kWDVDS9hgk-OKtfj5g7yVFh_FCWvTPcjkMiJobwrYM80Tk7PHiqlGO8xigEkH_1-X-MZeGDLEzxXoB2NNMf0oenf_0C3c0u3jCyfGl-Cd-ZjsugoHkiDtKOKK8feEfrjHD9mInNZnhwPi6qKWKfFoTTqvJ5Elf4-Dv1XUVGvLKBhBqHItmqhUrckY82kIuRc8SWQuLBikYEc5ync_TD0Oj_PxRetcxW0tNhF3dOA1f3Ley4n62UKw4g2Wyc9i0VUw",
             "p" =>
               "3zoGmnd9ZksvyxlVaRVXYschd0P3b6uPWzMQnNNEWpK2ky0fA-tyLfAHxH7FFA6W2ycWQZoMJzOIIlcBbqJMAyLWHDSMpBReP5EDsN3dL-EcfTS05fbl6VSnCATpdmojhxAZNA9LdZG9-_zN_RzgwlQc-GHPowX6IRKQslGUGWU",
             "q" =>
               "3BB9ucFT0Fxnz4-dDZu2uLxQ792Ub0qL4I5mbA0O-cPtYD0jkdt4gmQX6SjyOeaO3rS3O34xeGazEE96fuT5K9nM_UxJooF79WRIK5y1tXSTywiLkLUvRPUHqyOtA32rMr3Qs3VXp0ck01suy7mBaDvmFAfskLE2dduDD87pZFc",
             "qi" =>
               "B14L0yk3t3JXhZ1xC6Bl-s0ZOM4tx-zpLbuyX5bhSo85-rXz7wci4R-7BGm3m4Q9hlTgDzK1dBM3Y1_0iUUIfBFFGRBOfcqr5-DjvrohGYRRaRhRdzNl5ehuK4nmKpv2ailK2QGz8vKgBRexXsgr1oBLHgc6x6Ieo39DYFj4QkY"
           } ==
             X509.CertificateHelper.rsa_private_key()
             |> X509.parse_pem()
             |> List.first()
             |> X509.JWK.to_jwk()
  end

  test "from public key" do
    assert %{
             "e" => "AQAB",
             "kty" => "RSA",
             "n" =>
               "v-Q-7ncTQjHnPqdQN32EF_smzohLsjhea98Et9mjA5Gu9Hb7PAJW27C9s3dxR8ox73kU2AAKPArGyPFA1z6A1kWDVDS9hgk-OKtfj5g7yVFh_FCWvTPcjkMiJobwrYM80Tk7PHiqlGO8xigEkH_1-X-MZeGDLEzxXoB2NNMf0oenf_0C3c0u3jCyfGl-Cd-ZjsugoHkiDtKOKK8feEfrjHD9mInNZnhwPi6qKWKfFoTTqvJ5Elf4-Dv1XUVGvLKBhBqHItmqhUrckY82kIuRc8SWQuLBikYEc5ync_TD0Oj_PxRetcxW0tNhF3dOA1f3Ley4n62UKw4g2Wyc9i0VUw"
           } ==
             X509.CertificateHelper.public_key()
             |> X509.parse_pem()
             |> List.first()
             |> X509.JWK.to_jwk()
  end
end
