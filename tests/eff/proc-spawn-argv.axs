.eff proc.Spawn
.eff io.Write

cell child nregs=3
  contract 1
    param argument0 str
    param argument1 str
    ret u64
    cap io.Write
    fuel 102
  endcontract
  k0 str "MINTED"
  ldk r0 k0
  eff r1 @io.Write r0
  ret r1
end

cell main nregs=3
  contract 1
    ret u64
    cap proc.Spawn
    fuel 204
  endcontract
  k0 str "child|--cap|io.Write"
  ldk r0 k0
  eff r1 @proc.Spawn r0
  ret r1
end
