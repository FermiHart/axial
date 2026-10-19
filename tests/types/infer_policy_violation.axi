.eff fs.Read
.eff io.Write

policy decide : fn(c: cap io.Write, p: str) -> bool
  cap fs.Read
  fuel 500_000
{
  c.write(p)
  ret true
}
