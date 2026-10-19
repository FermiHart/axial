.eff fs.Read

cell main nregs=3
  contract 1
    ret str
    cap fs.Read
    fuel 10
  endcontract
  k0 str "tests/eff/data.txt"
  ldk r0 k0
  eff r0 @fs.Read r0
  ret r0
end
