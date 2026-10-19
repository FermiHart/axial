.eff net.Connect
.eff net.Write

cell main nregs=5
  contract 1
    ret u64
    cap net.Connect
    cap net.Write
    fuel 207
  endcontract
  k0 str "127.0.0.1:PORT"
  ldk r0 k0
  eff r1 @net.Connect r0
  # The malformed field starts with the actual live token, not a dead slot.
  k1 u64 4294967296
  ldk r4 k1
  eq r4 r1 r4
  jf r4 +2
  jmp +2
  ret r1
  k2 str "4294967296junk|x"
  ldk r2 k2
  eff r3 @net.Write r2
  ret r3
end
