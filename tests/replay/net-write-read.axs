.eff net.Connect
.eff net.Read
.eff net.Write

cell main nregs=5
  contract 1
    ret str
    cap net.Connect
    cap net.Read
    cap net.Write
    fuel 28
  endcontract
  k0 str "127.0.0.1:PORT"
  ldk r0 k0
  eff r1 @net.Connect r0

  k1 str "0|hello"
  ldk r2 k1
  eff r3 @net.Write r2

  k2 str "0|1024"
  ldk r2 k2
  eff r3 @net.Read r2

  ret r3
end
