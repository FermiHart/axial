.eff fs.Read
.eff fs.Write

policy decide : fn(input: json) -> bool
  cap fs.Read, fs.Write
{
  let target = input.args[0]
  if target under "/home/agent/workspace" { ret true }
  ret false
}
