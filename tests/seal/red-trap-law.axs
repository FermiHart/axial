cell law_boom nregs=4
  contract 1
    ret bool
    fuel 1000000
    pure
  endcontract
  k0 u64 0
  k1 u64 1
  ldk r1 k1
  ldk r2 k0
  div r3 r1 r2
  ret r3
end
