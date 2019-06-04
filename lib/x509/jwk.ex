defmodule X509.JWK do
  @signing_usages MapSet.new([
                    :digitalSignature,
                    :nonRepudiation,
                    :keyCertSign,
                    :cRLSign
                  ])

  def to_jwk(%X509.Certificate{} = cert) do
    x5t = X509.Certificate.thumbprint(cert, :sha) |> Base.encode64()
    x5t256 = X509.Certificate.thumbprint(cert, :sha256) |> Base.encode64()
    alg = X509.Certificate.alg(cert) |> jwk_alg()
    issuer = X509.Certificate.issuer_common_name(cert)

    serial = X509.Certificate.serial(cert) |> int_to_b64()

    usage = X509.Certificate.usage(cert) |> jwk_usage()
    public_key = X509.Certificate.public_key(cert) |> jwk_public_key()

    %{}
    |> Map.merge(public_key)
    |> Map.put("alg", alg)
    |> Map.put("use", usage)
    |> Map.put("kid", "#{issuer}/#{serial}")
    |> Map.put("x5t", x5t)
    |> Map.put("x5t#S256", x5t256)
    |> Map.put("x5c", X509.Certificate.b64(cert))
  end

  def to_jwk({:rsa_private_key, key_params}) do
    key_params
    |> Enum.into(%{}, fn {k, v} -> {to_string(k), X509.JWK.int_to_b64(v)} end)
    |> Map.put("kty", "RSA")
  end

  def to_jwk({:public_key, public_key}), do: jwk_public_key(public_key)

  def jwk_usage(usages) do
    case MapSet.disjoint?(MapSet.new(usages), @signing_usages) do
      true -> "enc"
      false -> "sig"
    end
  end

  def jwk_alg(alg) do
    case alg do
      {:rsa_pkcs1, :sha256} -> "RS256"
      {:rsa_pkcs1, :sha224} -> "RS224"
      {:rsa_pkcs1, :sha384} -> "RS384"
      {:rsa_pkcs1, :sha512} -> "RS512"
      {:rsa_pkcs1, hash} when hash in [:sha1, :md2, :md5] -> "RS256"
      :rsa_pkcs1 -> "RS256"
    end
  end

  def jwk_public_key({:rsa_pkcs1, %{n: n, e: e}}),
    do: %{
      "kty" => "RSA",
      "n" => n |> int_to_b64(),
      "e" => e |> int_to_b64()
    }

  def int_to_b64(num) do
    hex =
      num
      |> Integer.to_string(16)

    hex =
      case hex |> String.length() |> rem(2) do
        0 -> hex
        _ -> "0#{hex}"
      end

    hex
    |> Base.decode16!()
    |> Base.url_encode64(padding: false)
  end
end
