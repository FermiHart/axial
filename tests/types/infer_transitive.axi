cell leaf : fn() -> bool
  fuel 100
{
  ret fs.path_under("/home/agent/workspace/file", "/home/agent/workspace")
}

cell helper : fn() -> bool
  fuel 100
{
  ret leaf()
}

policy decide : fn() -> bool
  cap fs.Read
  fuel 500_000
{
  ret helper()
}
