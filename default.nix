with import <nixpkgs> {};
stdenv.mkDerivation {
  name = "libsoerudp-0.1";

  buildInputs = [ zlib ];

  src = ./.;

  installPhase = ''
    mkdir -p $out/lib

    cp ./bin/libsoerudp.* $out/lib
    cp --recursive ./include $out
  '';
}
