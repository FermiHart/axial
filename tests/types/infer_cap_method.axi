.eff fs.Read

cell read_path : fn(c: cap fs.Read, p: str) -> ok
  cap fs.Read
  fuel 102
{
  c.read(p)
  ret ok
}
