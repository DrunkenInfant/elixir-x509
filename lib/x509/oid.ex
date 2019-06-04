defmodule X509.OID do
  # Common OIDs
  # See https://tools.ietf.org/html/rfc5280,
  # https://tools.ietf.org/html/rfc3279 and https://tools.ietf.org/html/rfc4055
  # for more
  #
  # id-pkix: { 1 3 6 1 5 5 7 }
  # id-pe: { id-pkix 1 }
  # id-ce: { 2 5 29 }

  def ext_subject_kid, do: {2, 5, 29, 14}
  def ext_usage, do: {2, 5, 29, 15}
  def ext_basic_constraint, do: {2, 5, 29, 19}
  def ext_authority_kid, do: {2, 5, 29, 35}
  def ext_extended_key_usage, do: {2, 5, 29, 37}

  def ext_crl_distribution_point, do: {2, 5, 29, 31}
  def ext_subject_directory_attributes, do: {2, 5, 29, 9}
  def ext_subject_alt_name, do: {2, 5, 29, 17}
  def ext_issuer_alt_name, do: {2, 5, 29, 18}
  def ext_name_constraints, do: {2, 5, 29, 30}
  def ext_certificate_policies, do: {2, 5, 29, 32}
  def ext_policy_mappings, do: {2, 5, 29, 33}
  def ext_policy_constraints, do: {2, 5, 29, 36}
  def ext_authority_information_access, do: {1, 3, 6, 1, 5, 5, 7, 1, 1}

  def at_common_name, do: {2, 5, 4, 3}

  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 1}), do: :rsa_pkcs1
  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 5}), do: {:rsa_pkcs1, :sha1}
  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 11}), do: {:rsa_pkcs1, :sha256}
  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 14}), do: {:rsa_pkcs1, :sha224}
  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 12}), do: {:rsa_pkcs1, :sha384}
  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 13}), do: {:rsa_pkcs1, :sha512}
  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 2}), do: {:rsa_pkcs1, :md2}
  def translate_algorithm({1, 2, 840, 113_549, 1, 1, 4}), do: {:rsa_pkcs1, :md5}

  def translate_extended_key_usage({2, 5, 29, 37, 0}), do: :any
  def translate_extended_key_usage({1, 3, 6, 1, 5, 5, 7, 3, 1}), do: :serverAuth
  def translate_extended_key_usage({1, 3, 6, 1, 5, 5, 7, 3, 2}), do: :clientAuth
  def translate_extended_key_usage({1, 3, 6, 1, 5, 5, 7, 3, 3}), do: :codeSigning
  def translate_extended_key_usage({1, 3, 6, 1, 5, 5, 7, 3, 4}), do: :emailProtection
  def translate_extended_key_usage({1, 3, 6, 1, 5, 5, 7, 3, 8}), do: :timeStamping
  def translate_extended_key_usage({1, 3, 6, 1, 5, 5, 7, 3, 9}), do: :OCSPSigning

  def parse(<<v::size(8), rest::binary>>) do
    first = div(v, 40)
    sec = rem(v, 40)
    start = case first do
      0 -> [sec]
      _ -> [first, sec]
    end
    start ++ parse_next(rest) |> Enum.reduce({}, &Tuple.append(&2, &1))
  end

  def parse_next(<<>>), do: []

  def parse_next(data) do
    {vlq, rest} = collect_vlq(data)
    bsize = bit_size(vlq)
    <<val::unsigned-integer-size(bsize)>> = vlq
    [val | parse_next(rest)]
  end

  def collect_vlq(<<1::size(1), v::size(7), rest::binary>>) do
    {vlq, rest} = collect_vlq(rest)
    {<<v::size(7), vlq::bits>>, rest}
  end

  def collect_vlq(<<0::size(1), v::size(7), rest::binary>>) do
    {<<v::size(7)>>, rest}
  end
end
