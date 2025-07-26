{
  description = "Hash go brr";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in {
      packages.x86_64-linux.default = pkgs.stdenv.mkDerivation {
        pname = "salt-crack";
        version = "1.0";

        src = ./.;

        buildInputs = [
          pkgs.gcc
          pkgs.libxcrypt
        ];

        buildPhase = ''
          gcc -O3 -pthread salt_crack.c -o salt_crack -lcrypt
        '';

        installPhase = ''
          mkdir -p $out/bin
          cp salt_crack $out/bin/
        '';

        meta = with pkgs.lib; {
          description = "Multithreaded salt cracking using SHA512-crypt";
          license = licenses.mit;
          maintainers = with maintainers; [];
        };
      };

      defaultPackage.x86_64-linux = self.packages.x86_64-linux.default;

      defaultApp.x86_64-linux = {
        type = "app";
        program = "${self.packages.x86_64-linux.default}/bin/salt_crack";
      };
    };
}