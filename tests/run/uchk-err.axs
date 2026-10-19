cell may_fail nregs=6
  contract 1
    ret u64
    ret i64
    fuel 4
    pure
  endcontract
  k0 u64 0
  k1 u64 7
  ldk r1 k0
  ldk r2 k1
  umake r3 r1 r2
  ret r3
end

cell caller nregs=6
  contract 1
    ret u64
    fuel 11
    pure
  endcontract
  call r1 @may_fail 0
  uchk r2 r1
  ret r2
end

cell may_err nregs=6
  contract 1
    ret u64
    ret i64
    fuel 4
    pure
  endcontract
  k0 u64 1
  k1 i64 13
  ldk r1 k0
  ldk r2 k1
  umake r3 r1 r2
  ret r3
end

cell caller_err nregs=6
  contract 1
    ret u64
    ret i64
    fuel 10
    pure
  endcontract
  call r1 @may_err 0
  uchk r2 r1
  ret r2
end
