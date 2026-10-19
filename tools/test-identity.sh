#!/bin/sh
# Deterministic PUBLIC fixture identity. For tests and demonstrations only.
# SPDX-License-Identifier: LicenseRef-SPL-1.0
axi_test_identity() {
    [ "$#" -eq 1 ] && [ -d "$1" ] || return 1
    printf '\000\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037' >"$1/test.seed" || return 1
    printf '\003\241\007\277\363\316\020\276\035\160\335\030\347\113\300\231\147\344\326\060\233\245\015\137\035\334\206\144\022\125\061\270' >"$1/test.pk" || return 1
    [ "$(wc -c <"$1/test.seed")" -eq 32 ] && [ "$(wc -c <"$1/test.pk")" -eq 32 ]
}
