defmodule X509.CertificateTest do
  use ExUnit.Case

  test "parse public key" do
    cert = X509.Certificate.from_pem(X509.CertificateHelper.x509_public())

    assert {:rsa_pkcs1,
            %{
              e: 65537,
              n:
                29_234_923_440_473_393_399_107_002_360_566_702_558_104_745_176_696_051_336_761_158_286_127_532_418_725_940_542_333_277_795_585_387_581_948_649_406_931_791_720_478_091_540_165_622_983_911_021_447_515_085_688_599_894_030_909_739_575_943_742_148_006_834_337_468_111_724_687_356_646_608_137_330_558_401_928_754_727_790_589_580_808_805_528_648_216_950_817_228_342_088_930_620_778_397_299_111_301_988_761_278_599_735_451_663_449_654_427_924_889_366_130_832_206_027_242_376_769_041_096_172_251_710_776_844_051_614_056_117_409_223_206_406_913_226_622_408_126_521_458_370_613_079_510_879_470_485_884_576_347_279_423_338_099_592_837_020_147_097_110_636_427_711_736_500_376_077_322_683_528_735_491_016_477_262_681_691_386_166_578_774_039_552_067_407_061_450_034_853_278_398_546_637_379_108_861_808_754_600_589_082_401_136_423_068_127
            }} == X509.Certificate.public_key(cert)
  end

  test "parse usage" do
    cert = X509.Certificate.from_pem(X509.CertificateHelper.x509_public())
    assert [:digitalSignature, :keyEncipherment, :keyAgreement] == X509.Certificate.usage(cert)
  end

  test "parse extended key usage" do
    cert = X509.Certificate.from_pem(X509.CertificateHelper.x509_public())
    assert [:clientAuth] == X509.Certificate.extended_key_usage(cert)
  end
end
