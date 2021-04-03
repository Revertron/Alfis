#!/bin/sh

# This is a lazy script to create a .deb for Debian/Ubuntu. It installs
# ALFIS and enables it in systemd. You can give it the PKGARCH= argument
# i.e. PKGARCH=i386 sh contrib/deb/generate.sh

if [ `pwd` != `git rev-parse --show-toplevel` ]
then
  echo "You should run this script from the top-level directory of the git repo"
  exit 1
fi

PKGBRANCH=$(basename `git name-rev --name-only HEAD`)
PKGNAME=$(sh contrib/semver/name.sh)
PKGVERSION=$(sh contrib/semver/version.sh --bare)
PKGARCH=${PKGARCH-amd64}
PKGFILE=$PKGNAME-$PKGVERSION-$PKGARCH.deb
PKGREPLACES=alfis

#if [ $PKGBRANCH = "master" ]; then
#  PKGREPLACES=alfis-develop
#fi

# Building nogui versions only
if [ $PKGARCH = "amd64" ]; then cargo build --release --no-default-features --target x86_64-unknown-linux-musl && cp target/x86_64-unknown-linux-musl/release/alfis ./alfis
elif [ $PKGARCH = "i686" ]; then cross build --target i686-unknown-linux-gnu --release --no-default-features && cp target/i686-unknown-linux-gnu/release/alfis ./alfis
elif [ $PKGARCH = "mipsel" ]; then cross build --release --no-default-features --target mipsel-unknown-linux-gnu && cp target/mipsel-unknown-linux-gnu/release/alfis ./alfis
elif [ $PKGARCH = "mips" ]; then cross build --release --no-default-features --target mips-unknown-linux-gnu && cp target/mips-unknown-linux-gnu/release/alfis ./alfis
elif [ $PKGARCH = "armhf" ]; then cross build --release --no-default-features --target armv7-unknown-linux-gnueabihf && cp target/armv7-unknown-linux-gnueabihf/release/alfis ./alfis
elif [ $PKGARCH = "arm64" ]; then cross build --release --no-default-features --target aarch64-unknown-linux-gnu && cp target/aarch64-unknown-linux-gnu/release/alfis ./alfis
else
  echo "Specify PKGARCH=amd64,i686,mips,mipsel,armhf,arm64,armel"
  exit 1
fi

echo "Building $PKGFILE"

mkdir -p /tmp/$PKGNAME/
mkdir -p /tmp/$PKGNAME/debian/
mkdir -p /tmp/$PKGNAME/usr/bin/
mkdir -p /tmp/$PKGNAME/etc/systemd/system/

cat > /tmp/$PKGNAME/debian/changelog << EOF
Please see https://github.com/Revertron/Alfis/
EOF
echo 9 > /tmp/$PKGNAME/debian/compat
cat > /tmp/$PKGNAME/debian/control << EOF
Package: $PKGNAME
Version: $PKGVERSION
Section: contrib/net
Priority: extra
Architecture: $PKGARCH
Replaces: $PKGREPLACES
Conflicts: $PKGREPLACES
Maintainer: Revertron <revertron@users.noreply.github.com>
Description: ALFIS
 ALFIS (ALternative Free Identity System) is an implementation of a Domain Name System
 based on a small, slowly growing blockchain. It is lightweight, self-contained,
 supported on multiple platforms and contains DNS-resolver on its own to resolve domain records
 contained in blockchain and forward DNS requests of ordinary domain zones to upstream forwarders.
EOF
cat > /tmp/$PKGNAME/debian/copyright << EOF
Please see https://github.com/Revertron/Alfis/
EOF
cat > /tmp/$PKGNAME/debian/docs << EOF
Please see https://github.com/Revertron/Alfis/
EOF
cat > /tmp/$PKGNAME/debian/install << EOF
usr/bin/alfis usr/bin
etc/systemd/system/*.service etc/systemd/system
EOF
cat > /tmp/$PKGNAME/debian/postinst << EOF
#!/bin/sh -e

if ! getent group alfis 2>&1 > /dev/null; then
  groupadd --system --force alfis || echo "Failed to create group 'alfis' - please create it manually and reinstall"
fi

if ! getent passwd alfis >/dev/null 2>&1; then
    adduser --system --ingroup alfis --disabled-password --home /var/lib/alfis alfis
fi

mkdir -p /var/lib/alfis
chgrp alfis /var/lib/alfis

if [ -f /etc/alfis.conf ];
then
  mkdir -p /var/backups
  echo "Backing up configuration file to /var/backups/alfis.conf.`date +%Y%m%d`"
  cp /etc/alfis.conf /var/backups/alfis.conf.`date +%Y%m%d`
  echo "Updating /etc/alfis.conf"
  /usr/bin/alfis -u /var/backups/alfis.conf.`date +%Y%m%d` > /etc/alfis.conf
  chgrp alfis /etc/alfis.conf

  if command -v systemctl >/dev/null; then
    systemctl daemon-reload >/dev/null || true
    systemctl enable alfis || true
    systemctl start alfis || true
  fi
else
  echo "Generating initial configuration file /etc/alfis.conf"
  echo "Please familiarise yourself with this file before starting ALFIS"
  sh -c 'umask 0027 && /usr/bin/alfis -g > /etc/alfis.conf'
  chgrp alfis /etc/alfis.conf
fi
EOF
cat > /tmp/$PKGNAME/debian/prerm << EOF
#!/bin/sh
if command -v systemctl >/dev/null; then
  if systemctl is-active --quiet alfis; then
    systemctl stop alfis || true
  fi
  systemctl disable alfis || true
fi
EOF

sudo cp alfis /tmp/$PKGNAME/usr/bin/
cp contrib/systemd/*.service /tmp/$PKGNAME/etc/systemd/system/

tar -czvf /tmp/$PKGNAME/data.tar.gz -C /tmp/$PKGNAME/ \
  usr/bin/alfis \
  etc/systemd/system/alfis.service \
  etc/systemd/system/alfis-default-config.service
tar -czvf /tmp/$PKGNAME/control.tar.gz -C /tmp/$PKGNAME/debian .
echo 2.0 > /tmp/$PKGNAME/debian-binary

ar -r $PKGFILE \
  /tmp/$PKGNAME/debian-binary \
  /tmp/$PKGNAME/control.tar.gz \
  /tmp/$PKGNAME/data.tar.gz

rm -rf /tmp/$PKGNAME
