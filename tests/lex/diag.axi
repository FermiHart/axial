# diagnostic battery — every line below must produce a caged diag, rc=1
cell bad : fn() -> u64 fuel 1
{
  let a = 12ab
  let e = "bad escape \q ok"
  let u = @
  let z = "never closed
  ret 1
}
