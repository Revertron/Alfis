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
        lib = pkgs.lib;
        naersk-lib = naersk.lib.${system};
        isLinux = pkgs.stdenv.hostPlatform.isLinux;

        guiBuildInputs = lib.optionals isLinux (with pkgs; [
          gtk3
          webkitgtk_4_1
          xdotool
          libayatana-appindicator
        ]);

        guiNativeBuildInputs = [ pkgs.pkg-config ]
          ++ lib.optionals isLinux [ pkgs.makeWrapper pkgs.wrapGAppsHook ];

        guiRuntimeTools = lib.optionals isLinux [ pkgs.kdePackages.kdialog ];
        guiRuntimeLibPath = lib.optionalString isLinux (lib.makeLibraryPath guiBuildInputs);

        alfis = { webgui ? true, doh ? true }:
          let
            features = builtins.concatStringsSep " " (builtins.concatMap
              ({ option, features }: lib.optionals option features) [
                {
                  option = webgui;
                  features = [ "webgui" ];
                }
                {
                  option = doh;
                  features = [ "doh" ];
                }
              ]);
          in naersk-lib.buildPackage {
            pname = "alfis";
            root = ./.;
            nativeBuildInputs = guiNativeBuildInputs;
            buildInputs = guiBuildInputs;
            cargoBuildOptions = opts:
              opts ++ [ "--no-default-features" ]
              ++ lib.optionals (features != "") [ "--features" features ];
            preFixup = lib.optionalString isLinux ''
              gappsWrapperArgs+=(--prefix PATH : "${lib.makeBinPath guiRuntimeTools}")
              gappsWrapperArgs+=(--prefix LD_LIBRARY_PATH : "${guiRuntimeLibPath}")
            '';
          };
      in rec {
        packages = {
          alfis = alfis {
            webgui = true;
            doh = true;
          };
          alfisWithoutGUI = alfis {
            webgui = false;
            doh = true;
          };
        };

        defaultPackage = packages.alfis;

        apps = with flake-utils.lib; {
          alfis = mkApp { drv = packages.alfis; };
          alfisWithoutGUI = mkApp { drv = packages.alfisWithoutGUI; };
        };

        defaultApp = apps.alfis;
        devShell = import ./shell.nix { inherit pkgs; };
      });
}
