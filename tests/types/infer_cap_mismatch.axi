.eff fs.Read
.eff io.Write

cell read_path : fn(c: cap io.Write, p: str) -> ok
  cap fs.Read
  fuel 100
{
  c.write(p)
  ret ok
}
