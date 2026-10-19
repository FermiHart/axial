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
