.eff io.Write

cell fib nregs=8
  contract 1
    param n u64
    ret u64
    fuel 84
    pure
  endcontract
  k0 u64 0
  k1 u64 1
  ldk r1 k0
  ldk r2 k1
  ldk r5 k0
  ldk r6 k1
  eq r3 r0 r5
  jf r3 +2
  ret r1
  add r4 r1 r2
  mov r1 r2
  mov r2 r4
  sub r0 r0 r6
  jmp -7
end
cell greet nregs=3
  contract 1
    ret u64
    cap io.Write
    fuel 102
  endcontract
  k0 str "beyond"
  k1 err "io.denied"
  ldk r1 k0
  eff r2 @io.Write r1
  ret r2
end
