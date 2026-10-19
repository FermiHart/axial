.eff fs.Read

policy decide : fn(input: json) -> bool
  cap fs.Read
  fuel 500_000
{
  let target = json.get(input, "$.args[0]")
  if fs.path_under(target, "/home/agent/workspace") { ret true }
  ret false
}
