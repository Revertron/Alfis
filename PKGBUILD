pkgname=alfis
pkgver=0.3.12
pkgrel=1
pkgdesc="Alternative Free Identity System"
arch=('x86_64')
license=('AGPL3')
url='https://github.com/Revertron/Alfis'
depends=('webkit2gtk')
backup=("etc/$pkgname.toml")
source=("https://github.com/Revertron/Alfis/releases/download/v${pkgver}/alfis-linux-amd64-v${pkgver}.zip")
sha256sums=('SKIP')

package() {
	cd "$srcdir"
	install -Dm 755 "$pkgname"          "$pkgdir/usr/bin/$pkgname"
	install -Dm 644 "$pkgname.toml"     "$pkgdir/etc/$pkgname.toml"
}
