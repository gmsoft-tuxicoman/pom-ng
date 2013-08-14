# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4

DESCRIPTION="Packet-o-matic NG"
HOMEPAGE="http://www.packet-o-matic.org"
SRC_URI=""

LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="~amd64"

DEPEND="net-analyzer/pom-ng"
RDEPEND="${DEPEND}"

inherit git-2 autotools

EGIT_REPO_URI="git://github.com/gmsoft-tuxicoman/pom-ng-addons.git"

POMNG_ADDONS_DIR="/usr/share/pom-ng/addons/"

src_install() {

	dodir "${POMNG_ADDONS_DIR}"
	cp -R "${S}/"*.lua "${D}/${POMNG_ADDONS_DIR}" || die "doins failed"

	dodoc "${S}/README"

}
