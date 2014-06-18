# Copyright 1999-2012 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=5

DESCRIPTION="Packet-o-matic NG"
HOMEPAGE="http://www.packet-o-matic.org"

LICENSE="GPL-2+"
SLOT="0"
KEYWORDS="~amd64"
IUSE="magic pcap zlib jpeg sqlite exif postgres sqlite dvb"

SRC_URI=""
GITHUB_URI="git://github.com/gmsoft-tuxicoman"
GIT_REPOS="pom-ng pom-ng-addons pom-ng-webui"
inherit git-2
KEYWORDS=""

MY_S="${S}"
S="${WORKDIR}/${P}/pom-ng"

DEPEND="
	net-libs/libmicrohttpd[messages]
	dev-libs/libxml2
	dev-libs/uthash
	dev-libs/xmlrpc-c[threads]
	=dev-lang/lua-5.1*
	magic? ( sys-apps/file )
	pcap? ( net-libs/libpcap )
	zlib? ( sys-libs/zlib )
	jpeg? ( virtual/jpeg )
	sqlite? ( dev-db/sqlite )
	exif? ( media-libs/libexif )
	postgres? ( dev-db/postgresql-base )"

inherit git-2 autotools

src_unpack() {

	for REPO in $GIT_REPOS
	do
		EGIT_REPO_URI="${GITHUB_URI}"/"${REPO}".git
		EGIT_SOURCEDIR="${MY_S}/${REPO}"
		einfo Unpacking $EGIT_REPO_URI
		git-2_src_unpack
	done

}

src_prepare() {
	eautoreconf
}

src_configure() {
	econf \
		$(use_with magic) \
		$(use_with pcap) \
		$(use_with dvb) \
		$(use_with zlib) \
		$(use_with sqlite sqlite3) \
		$(use_with postgres) \
		$(use_with exif)
}


src_install() {
	default
	insinto /usr/share/pom-ng/addons
	doins ${MY_S}/pom-ng-addons/*
	insinto /usr/share/pom-ng/pom-ng-webui
	doins ${MY_S}/pom-ng-webui/*
}
