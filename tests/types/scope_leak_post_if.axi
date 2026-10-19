.eff io.Write

cell main : fn() -> u64
  fuel 1_000
  pure
{
  if true { let x = 5 }
  ret x
}
