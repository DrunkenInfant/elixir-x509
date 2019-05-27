# X509

Parse and fomat X509 certificates.

## Installation

```elixir
def deps do
  [
    {:x509, git: "https://github.com/PlugAndTrade/elixir-x509.git"}
  ]
end
```

## Usage

```
> pem = "<<pem formated x509 certificates>>"
> cert = X509.Certificate.from_pem(pem)
> X509.JWK.to_jwk(cert)
```
