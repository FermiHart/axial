cell main nregs=4
  contract 1
    ret u64
    fuel 21
    pure
  endcontract
  k0 u64 1
  ldk r1 k0
  ldk r2 k0
  add r2 r2 r1
  jmp -1
end
