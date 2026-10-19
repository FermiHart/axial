.eff proc.Spawn

cell child nregs=2
  contract 1
    ret u64
    fuel 2
    pure
  endcontract
  k0 u64 42
  ldk r0 k0
  ret r0
end

cell main nregs=3
  contract 1
    ret u64
    cap proc.Spawn
    fuel 12
  endcontract
  k0 str "child"
  ldk r0 k0
  eff r1 @proc.Spawn r0
  ret r1
end
