.eff net.Connect
.eff net.Read
.eff net.Write

cell main nregs=5
  contract 1
    ret str
    cap net.Connect
    cap net.Read
    cap net.Write
    fuel 308
  endcontract
  k0 str "127.0.0.1:PORT"
  ldk r0 k0
  eff r1 @net.Connect r0
  # Private CLI fixture token: generation 1, slot 0. Check before use.
  k1 u64 4294967296
  ldk r4 k1
  eq r4 r1 r4
  jf r4 +2
  jmp +2
  ret r1

  k2 str "4294967296|hello"
  ldk r2 k2
  eff r3 @net.Write r2

  k3 str "4294967296|1024"
  ldk r2 k3
  eff r3 @net.Read r2

  ret r3
end
