defmodule X509 do
  @moduledoc """
  Documentation for X509.
  """

  def parse_pem(pem) do
    pem
    |> String.replace("\n", "")
    |> (&Regex.scan(~r/-----BEGIN ([^-]+?)-----(.+?)-----END \1-----/, &1)).()
    |> Enum.map(fn [_, typ, b64] -> parse_der(typ, Base.decode64!(b64)) end)
  end

  def parse_der("RSA PRIVATE KEY", der) do
    {:rsa_private_key, X509.PKCS.RSA.parse_private_key(der)}
  end

  def parse_der("PUBLIC KEY", der) do
    {:public_key, X509.PKCS.RSA.parse_public_key(der)}
  end
end
