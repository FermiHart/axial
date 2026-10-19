.eff net.Connect

cell main nregs=3
  contract 1
    ret u64
    cap net.Connect
    fuel 102
  endcontract
  k0 str "127.0.0.1:PORT"
  ldk r0 k0
  eff r1 @net.Connect r0
  ret r1
end
