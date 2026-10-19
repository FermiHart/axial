cell main nregs=4
  contract 1
    ret u64
    fuel 3
    pure
  endcontract
  k0 u64 1
  ldk r1 k0
  add r2 r1 r1
  ret r2
end
