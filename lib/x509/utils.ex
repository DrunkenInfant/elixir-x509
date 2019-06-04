defmodule X509.Utils do
  def bin_as_bitlist(bin),
    do: bin
        |> :binary.bin_to_list()
        |> Enum.map(&byte_as_bitlist(<<&1::size(8)>>))
        |> Enum.reduce([], &Kernel.++/2)

  def byte_as_bitlist(<<b::size(1), rest::bitstring>>), do: [b | byte_as_bitlist(rest)]
  def byte_as_bitlist(<<>>), do: []
end
