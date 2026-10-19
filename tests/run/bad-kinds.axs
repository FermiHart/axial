cell main nregs=4
  contract 1
    ret u64
    fuel 3
    pure
  endcontract
  k0 u64 1
  k1 str "x"
  ldk r1 k0
  ldk r2 k1
  add r3 r1 r2
  ret r3
end
