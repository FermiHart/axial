cell a : fn(path: str, stop: bool) -> bool
  fuel 100
{
  if stop { ret fs.path_under(path, "/home/agent/workspace") }
  ret b(path, true)
}

cell b : fn(path: str, stop: bool) -> bool
  fuel 100
{
  ret a(path, stop)
}

policy decide : fn(path: str) -> bool
  cap fs.Read
  fuel 500_000
{
  ret b(path, false)
}
