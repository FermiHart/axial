.eff fs.Read
.eff fs.Write

policy decide : fn(input: json) -> bool
{
  ret true
}
