#!/opt/bin/bash

# ALFIS upgrade script for Keenetic routers with Entware

json=$(curl -s "https://api.github.com/repos/Revertron/Alfis/releases/latest")
upstreamver=$(echo "$json" | jq -r ".tag_name")

curver=$(alfis -v | cut -c7-25)

changed=$(diff <(echo "$curver") <(echo "$upstreamver"))

if [ "$changed" != "" ]
then
  echo "Upgrading from $curver to $upstreamver"
  /opt/etc/init.d/S98alfis stop
  wget https://github.com/Revertron/Alfis/releases/download/$upstreamver/alfis-linux-mipsel-$upstreamver-nogui -O /opt/bin/alfis
  chmod +x /opt/bin/alfis
  /opt/etc/init.d/S98alfis start
else
  echo "No need to upgrade, $curver is the current version"
fi