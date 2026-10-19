.eff proc.Spawn

cell child nregs=3
  contract 1
    ret u64
    fuel 100
    pure
  endcontract
  k0 u64 1
  ldk r0 k0
  mov r1 r0
  add r1 r1 r0
  jmp -1
end

cell main nregs=3
  contract 1
    ret u64
    cap proc.Spawn
    fuel 201
  endcontract
  k0 str "child"
  ldk r0 k0
  eff r1 @proc.Spawn r0
  ret r1
end
