cell double nregs=3
  contract 1
    param value u64
    ret u64
    fuel 4
    pure
  endcontract
  k0 u64 2
  ldk r1 k0
  mul r2 r0 r1
  ret r2
end
cell main nregs=6
  contract 1
    ret u64
    fuel 18
    pure
  endcontract
  k0 u64 3
  ldk r2 k0
  call r2 @double 1
  call r2 @double 1
  ret r2
end
