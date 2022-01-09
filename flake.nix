{
  description = "Alternative Free Identity System";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    naersk.url = "github:nmattia/naersk";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, naersk }:
    let
      systems = [
        "aarch64-linux"
        "aarch64-darwin"
        "i686-linux"
        "x86_64-darwin"
        "x86_64-linux"
        "i686-windows"
        "x86_64-windows"
      ];

    in flake-utils.lib.eachSystem systems (system:
      let

        pkgs = nixpkgs.legacyPackages.${system};

        naersk-lib = naersk.lib.${system};

        alfis = { webgui ? true, doh ? true, edge ? false }:
          let
            features = builtins.concatStringsSep " " (builtins.concatMap
              ({ option, features }: pkgs.lib.optionals option features) [
                {
                  option = webgui;
                  features = [ "webgui" ];
                }
                {
                  option = doh;
                  features = [ "doh" ];
                }
                {
                  option = edge;
                  features = [ "edge" ];
                }
              ]);
          in naersk-lib.buildPackage {
            pname = "alfis";
            nativeBuildInputs = with pkgs; [ pkg-config webkitgtk kdialog ];
            dontWrapQtApps = true;
            cargoBuildOptions = opts:
              opts ++ [ "--no-default-features" ]
              ++ [ "--features" ''"${features}"'' ];
            root = ./.;
          };

        isWindows = builtins.elem system [ "i686-windows" "x86_64-windows" ];
      in rec {

        packages = {
          alfis = alfis {
            webgui = true;
            doh = true;
            edge = false;
          };
          alfisWithoutGUI = alfis {
            webgui = false;
            doh = true;
            edge = false;
          };
        } // pkgs.lib.optionalAttrs isWindows {
          alfisEdge = alfis {
            webgui = false;
            doh = true;
            edge = true;
          };
        };

        defaultPackage = packages.alfis;

        apps = with flake-utils.lib;
          {
            alfis = mkApp { drv = packages.alfis; };
            alfisWithoutGUI = mkApp { drv = packages.alfisWithoutGUI; };
          } // pkgs.lib.optionalAttrs isWindows {
            alfisEdge = mkApp { drv = packages.alfisEdge; };
          };
        defaultApp = apps.alfis;

        devShell = import ./shell.nix { inherit pkgs; };

      });
}
