.eff net.Write

cell main nregs=2
  contract 1
    ret u64
    cap net.Write
    fuel 102
  endcontract
  k0 str "111111111111111111111111111111111|x"
  ldk r0 k0
  eff r1 @net.Write r0
  ret r1
end
