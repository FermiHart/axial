cell main nregs=4
  contract 1
    ret u64
    fuel 6
    pure
  endcontract
  k0 u64 7
  k1 u64 0
  ldk r1 k0
  ldk r2 k1
  div r3 r1 r2
  ret r3
end
