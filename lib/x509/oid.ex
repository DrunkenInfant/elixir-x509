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
end
