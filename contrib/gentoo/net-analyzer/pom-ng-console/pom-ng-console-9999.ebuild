# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=4

DESCRIPTION="Console for packet-o-matic NG"
HOMEPAGE="http://www.packet-o-matic.org"
SRC_URI=""

LICENSE=""
SLOT="0"
KEYWORDS="~amd64"
IUSE=""

DEPEND=""
RDEPEND="${DEPEND}"

inherit git-2 distutils

EGIT_REPO_URI="git://github.com/gmsoft-tuxicoman/pom-ng-console.git"
PYTHON_DEPEND="3"

pkg_setup() {
	python_set_active_version 3
	python_pkg_setup
}
