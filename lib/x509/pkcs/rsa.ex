defmodule X509.PKCS.RSA do
  # Implemented according to https://tools.ietf.org/html/rfc3447

  def parse_public_key(der) when is_binary(der),
    do: der |> X509.ASN1.parse() |> parse_public_key()

  def parse_public_key([sequence: [
        sequence: [oid: oid, null: ""],
        bit_string: <<0::size(8), pub_key::binary>>
  ]]), do: {
    X509.OID.translate_algorithm(oid),
    pub_key |> X509.ASN1.parse() |> parse_public_key()
  }

  def parse_public_key([{:sequence, [{:int, n}, {:int, e}]}]),
    do: %{n: n, e: e}

  def parse_private_key(der) when is_binary(der),
    do: der |> X509.ASN1.parse() |> parse_private_key()

  # Parse version 0 (two-prime) private key
  def parse_private_key([{:sequence, [
        {:int, 0},
        {:int, n},
        {:int, e},
        {:int, d},
        {:int, p},
        {:int, q},
        {:int, dp},
        {:int, dq},
        {:int, qi}
      ]}]),
    do: %{n: n, e: e, d: d, p: p, q: q, dp: dp, dq: dq, qi: qi}
end
