defmodule X509.ASN1 do
  def parse(<<>>), do: []

  def parse(data) do
    {element, rest} = parse_one(data)
    [element | parse(rest)]
  end

  def parse_one(<<class::size(2), 0::size(1), tag::size(5), rest::binary>>) do
    {val_size, rest} = parse_size(rest)
    <<val::binary-size(val_size), rest::binary>> = rest
    {format_value(tag_name(class, tag), val), rest}
  end

  def parse_one(<<class::size(2), 1::size(1), tag::size(5), rest::binary>>) do
    {val_size, rest} = parse_size(rest)
    <<val::binary-size(val_size), rest::binary>> = rest
    {{tag_name(class, tag), parse(val)}, rest}
  end

  def parse_size(<<1::size(1), size_len::size(7), s_b::binary-size(size_len), rest::binary>>),
    do: {:binary.bin_to_list(s_b) |> Integer.undigits(256), rest}

  def parse_size(<<0::size(1), s::size(7), rest::binary>>),
    do: {s, rest}

  def format_value(:int, val) do
    bsize = byte_size(val) * 8
    <<num::unsigned-integer-size(bsize)>> = val
    {:int, num}
  end

  def format_value(:bit_string, val) do
    # Reverse bits in each byte and reverse all bytes
    bitlist =
      val
      |> :binary.bin_to_list()
      |> Enum.map(&byte_as_bitlist(<<&1::size(8)>>))
      |> Enum.reduce([], &Kernel.++/2)

    {:bit_string, bitlist}
  end

  def format_value(tag, val), do: {tag, val}

  def tag_name(1, v), do: {:app_spec, v}
  def tag_name(2, v), do: {:ctx_spec, v}
  def tag_name(3, v), do: {:private, v}
  def tag_name(0, 0), do: :eoc
  def tag_name(0, 1), do: :bool
  def tag_name(0, 2), do: :int
  def tag_name(0, 3), do: :bit_string
  def tag_name(0, 4), do: :octet_string
  def tag_name(0, 5), do: :null
  def tag_name(0, 6), do: :oid
  def tag_name(0, 7), do: :obj_descr
  def tag_name(0, 8), do: :ext
  def tag_name(0, 9), do: :real
  def tag_name(0, 10), do: :enum
  def tag_name(0, 11), do: :embed_pdv
  def tag_name(0, 12), do: :utf8_string
  def tag_name(0, 13), do: :rel_oid
  def tag_name(0, 14), do: :reserved
  def tag_name(0, 15), do: :reserved
  def tag_name(0, 16), do: :sequence
  def tag_name(0, 17), do: :set
  def tag_name(0, 18), do: :num_string
  def tag_name(0, 19), do: :print_string
  def tag_name(0, 20), do: :t61_string
  def tag_name(0, 21), do: :videotex_string
  def tag_name(0, 22), do: :ia5_string
  def tag_name(0, 23), do: :utctime
  def tag_name(0, 24), do: :gen_time
  def tag_name(0, 25), do: :graphic_string
  def tag_name(0, 26), do: :visible_string
  def tag_name(0, 27), do: :gen_string
  def tag_name(0, 28), do: :universal_string
  def tag_name(0, 29), do: :char_string
  def tag_name(0, 30), do: :bmp_string

  def byte_as_bitlist(<<b::size(1), rest::bitstring>>), do: [b | byte_as_bitlist(rest)]
  def byte_as_bitlist(<<>>), do: []
end
