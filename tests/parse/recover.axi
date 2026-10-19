# diagnostic battery: every block below must diag + recover, rc=1
let stray = 1

cell nofuel : fn() -> u64
{
  ret 1
}

cell dupfuel : fn() -> u64
  fuel 10
  fuel 20
{
  let x =
  ret 1
}
