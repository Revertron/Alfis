{ pkgs ? import <nixpkgs> { } }:

let
  runtimeLibs = with pkgs; [
    gtk3
    webkitgtk_4_1
    xdotool
    libayatana-appindicator
  ];

  packages = with pkgs; [
    cargo
    rustc
    pkg-config
    kdePackages.kdialog
  ] ++ runtimeLibs;
in
pkgs.mkShell {
  buildInputs = packages;
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath runtimeLibs;
}
