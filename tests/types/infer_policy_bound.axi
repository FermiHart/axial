.eff fs.Read

policy decide : fn(c: cap fs.Read, p: str) -> bool
  cap fs.Read
  fuel 500_000
{
  c.read(p)
  ret true
}
