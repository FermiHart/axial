.eff io.Write

cell main nregs=3
  contract 1
    ret u64
    cap io.Write
    fuel 1000000
  endcontract
  k0 str "zero-dep supply chain artifact"
  ldk r1 k0
  eff r2 @io.Write r1
  ret r2
end

cell law_main_ok nregs=3
  contract 1
    ret bool
    fuel 1000000
    pure
  endcontract
  k0 u64 1
  k1 u64 1
  ldk r0 k0
  ldk r1 k1
  eq r2 r0 r1
  ret r2
end
