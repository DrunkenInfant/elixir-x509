defmodule X509.PKCS do
  def parse_private_key(der) when is_binary(der),
    do: der |> X509.ASN1.parse() |> parse_private_key()

  def parse_private_key([
        {:sequence,
         [
           int: 0,
           sequence: [oid: alg_id, null: _],
           octet_string: key_data
         ]}
      ]) do
    parse_private_key(X509.OID.translate_algorithm(alg_id), key_data)
  end

  def parse_private_key({:rsa_pkcs1, _}, rsa_private_key),
    do: parse_private_key(:rsa_pkcs1, rsa_private_key)

  def parse_private_key(:rsa_pkcs1, rsa_private_key) do
    {:rsa_private_key, X509.PKCS.RSA.parse_private_key(rsa_private_key)}
  end
end
