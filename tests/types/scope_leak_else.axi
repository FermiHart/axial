.eff io.Write

cell main : fn(b: bool) -> u64
  fuel 1_000
{
  if b { let x = 5 } else { ret x }
  ret 0
}
