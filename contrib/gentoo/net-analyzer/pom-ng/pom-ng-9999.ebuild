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
IUSE="magic pcap zlib jpeg sqlite console exif"

DEPEND="
	net-libs/libmicrohttpd
	dev-libs/libxml2
	dev-libs/xmlrpc-c[threads]
	=dev-lang/lua-5.1*
	magic? ( sys-apps/file )
	pcap? ( net-libs/libpcap )
	zlib? ( sys-libs/zlib )
	jpeg? ( virtual/jpeg )
	sqlite? ( dev-db/sqlite[threadsafe] )
	console? ( net-analyzer/pom-ng-console )
	exif? ( media-libs/libexif )"
RDEPEND="${DEPEND}"

inherit git-2 autotools

EGIT_REPO_URI="git://github.com/gmsoft-tuxicoman/pom-ng.git"

src_prepare() {
	eautoreconf
}

