.eff proc.Spawn

cell child nregs=2
  contract 1
    ret u64
    fuel 2
    pure
  endcontract
  k0 u64 43
  ldk r0 k0
  ret r0
end
