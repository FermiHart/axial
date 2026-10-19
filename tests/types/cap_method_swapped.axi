.eff fs.Read

cell m : fn(c: cap fs.Write, p: str) -> ok
  cap fs.Write
  fuel 100
{
  c.read(p)
  ret ok
}
