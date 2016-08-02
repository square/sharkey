#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

DIR=$(dirname $(readlink -f $0))

rev=$(git rev-parse HEAD)

tar -C "${DIR}/../.." -zcf ~/rpmbuild/SOURCES/sharkey-${rev}.tar.gz --transform s/sharkey/sharkey-${rev}/ sharkey
rpmbuild -ba ${DIR}/sharkey.spec
