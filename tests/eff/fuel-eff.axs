.eff fs.Read

cell test_fuel_eff nregs=3
  contract 1
    ret str
    cap fs.Read
    fuel 102
  endcontract
  k0 str "/etc/passwd"
  ldk r0 k0
  eff r0 @fs.Read r0
  ret r0
end
