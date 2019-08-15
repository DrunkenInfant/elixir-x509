defmodule X509.Certificate do
  import Record
  require Record

  @moduledoc """
  See http://erlang.org/doc/apps/public_key/public_key_records.html for record definitions
  """
  defrecord :certificate,
            :Certificate,
            Record.extract(:Certificate, from_lib: "public_key/include/public_key.hrl")

  defrecord :tbs_certificate,
            :TBSCertificate,
            Record.extract(:TBSCertificate, from_lib: "public_key/include/public_key.hrl")

  defrecord :subject_public_key_info,
            :SubjectPublicKeyInfo,
            Record.extract(:SubjectPublicKeyInfo, from_lib: "public_key/include/public_key.hrl")

  defrecord :algorithm_identifier,
            :AlgorithmIdentifier,
            Record.extract(:AlgorithmIdentifier, from_lib: "public_key/include/public_key.hrl")

  defrecord :erl_validity,
            :Validity,
            Record.extract(:Validity, from_lib: "public_key/include/public_key.hrl")

  defrecord :extension,
            :Extension,
            Record.extract(:Extension, from_lib: "public_key/include/public_key.hrl")

  defrecord :authority_key_identifier,
            :AuthorityKeyIdentifier,
            Record.extract(:AuthorityKeyIdentifier, from_lib: "public_key/include/public_key.hrl")

  defstruct der: <<>>,
            record: nil,
            issuer: nil

  @type t :: %__MODULE__{
          der: binary(),
          record: record(:certificate),
          issuer: __MODULE__.t()
        }

  def pem(%__MODULE__{record: record}) do
    pe = :public_key.pem_entry_encode(:Certificate, record)
    :public_key.pem_encode([pe])
  end

  def b64(%__MODULE__{der: der, issuer: nil}),
    do: [Base.encode64(der)]

  def b64(%__MODULE__{der: der, issuer: issuer}),
    do: [Base.encode64(der) | b64(issuer)]

  def der(%__MODULE__{der: der}), do: der

  def from_pem(pem) do
    pem
    |> String.replace("\n", "")
    |> (&Regex.scan(~r/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/, &1)).()
    |> Enum.map(fn [_, b64] -> Base.decode64!(b64) end)
    |> from_der()
  end

  def from_der([der]),
    do: %__MODULE__{
      der: der,
      record: :public_key.pkix_decode_cert(der, :plain),
      issuer: nil
    }

  def from_der([der | ca_chain]),
    do: %__MODULE__{
      der: der,
      record: :public_key.pkix_decode_cert(der, :plain),
      issuer: from_der(ca_chain)
    }

  def thumbprint(%__MODULE__{der: der}, alg \\ :sha256),
    do: :crypto.hash(alg, der)

  def serial(%__MODULE__{record: record}),
    do:
      record
      |> certificate(:tbsCertificate)
      |> tbs_certificate(:serialNumber)

  def public_key(%__MODULE__{record: record}) do
    spki =
      record
      |> certificate(:tbsCertificate)
      |> tbs_certificate(:subjectPublicKeyInfo)

    alg =
      spki
      |> subject_public_key_info(:algorithm)
      |> algorithm_identifier(:algorithm)
      |> X509.OID.translate_algorithm()

    key =
      spki
      |> subject_public_key_info(:subjectPublicKey)
      |> X509.PKCS.RSA.parse_public_key()

    {
      alg,
      key
    }
  end

  def validity(%__MODULE__{record: record}) do
    record
    |> certificate(:tbsCertificate)
    |> tbs_certificate(:validity)
    |> parse_validity()
  end

  def parse_validity(validity),
    do: {
      erl_validity(validity, :notBefore) |> parse_time(),
      erl_validity(validity, :notAfter) |> parse_time()
    }

  def parse_time({:utcTime, ans1_time}),
    do: Timex.parse!(to_string(ans1_time), "{ASN1:UTCtime}")

  def parse_time({:generalTime, ans1_time}),
    do: Timex.parse!(to_string(ans1_time), "{ASN1:GeneralizedTime:Z}")

  def issuer_common_name(%__MODULE__{record: record}),
    do:
      record
      |> certificate(:tbsCertificate)
      |> tbs_certificate(:issuer)
      |> rdn_sequence_find(X509.OID.at_common_name())

  def subject_kid(cert) do
    case extensions_find(cert, X509.OID.ext_subject_kid()) do
      nil -> nil
      {_asn1_type, sub_kid} -> sub_kid
    end
  end

  def authority_kid(cert) do
    case extensions_find(cert, X509.OID.ext_authority_kid()) do
      nil ->
        nil

      {:sequence, auth_kids} ->
        auth_kids
        |> Enum.map(fn {{:ctx_spec, ctx_spec}, val} ->
          {translate_authority_kid_spec(ctx_spec), val}
        end)
    end
  end

  def translate_authority_kid_spec(0), do: :keyIdentifier
  def translate_authority_kid_spec(1), do: :authorityCertIssuer
  def translate_authority_kid_spec(2), do: :authorityCertSerialNumber

  def usage(cert) do
    case extensions_find(cert, X509.OID.ext_usage()) do
      nil ->
        nil

      {:bit_string, usages} ->
        usages
        |> X509.Utils.bin_as_bitlist()
        |> Enum.with_index()
        |> Enum.reduce([], fn
          {0, _}, acc -> acc
          {_, idx}, acc when idx > 8 -> acc
          {_, idx}, acc -> [translate_usage(idx) | acc]
        end)
        |> Enum.reverse()
    end
  end

  def translate_usage(0), do: :digitalSignature
  def translate_usage(1), do: :nonRepudiation
  def translate_usage(2), do: :keyEncipherment
  def translate_usage(3), do: :dataEncipherment
  def translate_usage(4), do: :keyAgreement
  def translate_usage(5), do: :keyCertSign
  def translate_usage(6), do: :cRLSign
  def translate_usage(7), do: :encipherOnly
  def translate_usage(8), do: :decipherOnly

  def basic_constraint(cert) do
    case extensions_find(cert, X509.OID.ext_basic_constraint()) do
      nil -> nil
      {_asn1_type, bc} -> bc
    end
  end

  def extended_key_usage(cert) do
    case extensions_find(cert, X509.OID.ext_extended_key_usage()) do
      nil ->
        nil

      {:sequence, ext_ku} ->
        Enum.map(ext_ku, fn {:oid, oid} -> X509.OID.translate_extended_key_usage(oid) end)
    end
  end

  def alg(%__MODULE__{record: record}) do
    record
    |> certificate(:tbsCertificate)
    |> tbs_certificate(:subjectPublicKeyInfo)
    |> subject_public_key_info(:algorithm)
    |> algorithm_identifier(:algorithm)
    |> X509.OID.translate_algorithm()
  end

  defp extensions_find(%__MODULE__{record: record}, oid),
    do:
      record
      |> certificate(:tbsCertificate)
      |> tbs_certificate(:extensions)
      |> extensions_find(oid)

  defp extensions_find(:asn1_NOVALUE, _oid),
    do: nil

  defp extensions_find([], _oid),
    do: nil

  defp extensions_find([{_, oid, _crit, val} | _], oid),
    do: X509.ASN1.parse(val) |> List.first()

  defp extensions_find([_ | rest], oid),
    do: extensions_find(rest, oid)

  defp rdn_sequence_find({:rdnSequence, rdns}, oid) do
    case Enum.find_value(rdns, nil, &List.keyfind(&1, oid, 1)) do
      nil ->
        nil

      {_key, _oid, asn1_val} ->
        {_qualifier, val} = X509.ASN1.parse(asn1_val) |> List.first()
        val
    end
  end
end
