cell add2 nregs=4
  contract 1
    param value u64
    ret u64
    fuel 1000000
    pure
  endcontract
  k0 u64 2
  ldk r1 k0
  add r2 r0 r1
  ret r2
end
cell law_add2_works nregs=6
  contract 1
    ret bool
    fuel 1000000
    pure
  endcontract
  k0 u64 41
  k1 u64 42
  ldk r0 k0
  call r0 @add2 1
  ldk r2 k1
  eq r3 r0 r2
  ret r3
end
