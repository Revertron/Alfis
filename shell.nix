{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs =
    [ pkgs.cargo pkgs.rustc pkgs.webkitgtk pkgs.pkg-config pkgs.kdialog ];
}
