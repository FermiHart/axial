.eff fs.Write

cell test_fs_write nregs=3
  contract 1
    ret u64
    cap fs.Write
    fuel 102
  endcontract
  k0 str "written.txt|gate test content"
  ldk r0 k0
  eff r0 @fs.Write r0
  ret r0
end
