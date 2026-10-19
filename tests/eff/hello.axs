# W19 — the first program in this language that can touch the world.
.eff io.Write

cell main nregs=3
  contract 1
    ret u64
    cap io.Write
    fuel 102
  endcontract
  k0 str "metal na veia"
  ldk r1 k0
  eff r2 @io.Write r1
  ret r2
end
