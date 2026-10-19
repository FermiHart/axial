.eff fs.Read

cell check : fn(p: str) -> bool
  cap fs.Read
  fuel 100
{
  ret fs.exists(p)
}
