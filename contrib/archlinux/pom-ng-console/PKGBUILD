# Contributor: Guy Martin <gmsoft@tuxicoman.be>
# Maintainer: Gatien Bovyn <gatien.bovyn@gmail.com>
pkgname=pom-ng-console
pkgver=v0.0.3.1.gd9d8812
pkgrel=1
pkgdesc="Real time network forensic tool (console)."
url="http://www.packet-o-matic.org/"
license=('GPL')
arch=('any')
depends=('python3' 'pom-ng')
makedepends=('git')
provides=('pom-ng-console')
#install=$pkgname.install
source=('git://github.com/gmsoft-tuxicoman/pom-ng-console.git')
md5sums=('SKIP')

_gitname="pom-ng-console"


pkgver () {
  cd $_gitname/
  echo $(git describe --tags | sed 's/^release-//; s/-/./g')
}
 
package() {
  cd $_gitname/
  sudo python setup.py install
  sudo mv /usr/bin/pom-ng-console.py /usr/bin/pom-ng-console
}
