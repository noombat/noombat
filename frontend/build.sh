#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#
# `pnpm build`: build into dist.next/, then rename it into dist/'s place,
# the last build renamed aside first and removed after. A server reading
# dist/ meanwhile finds a whole build, old or new, and a failed build
# leaves the last one there. Arguments go to `vite build`.
set -eu
cd "$(dirname "$0")"
rm -rf dist.old
vite build --outDir dist.next "$@"
if [ -d dist ]; then mv dist dist.old; fi
mv dist.next dist
rm -rf dist.old
