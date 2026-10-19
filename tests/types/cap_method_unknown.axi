.eff fs.Read

cell m : fn(c: cap fs.Read, p: str) -> ok
  cap fs.Read
  fuel 100
{
  c.frobnicate(p)
  ret ok
}
