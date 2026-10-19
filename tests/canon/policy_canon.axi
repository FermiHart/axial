.eff fs.Read
.eff fs.Write

policy decide : fn(input: str) -> bool
  fuel 500_000
{
  ret true
}
