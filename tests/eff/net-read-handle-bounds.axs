.eff net.Read

cell main nregs=3
  contract 1
    ret str
    cap net.Read
    fuel 102
  endcontract
  k0 str "4294967296|1"
  ldk r0 k0
  eff r1 @net.Read r0
  ret r1
end
