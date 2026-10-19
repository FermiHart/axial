.eff fs.Read

cell workspace_root : fn() -> str
  fuel 100
{
  ret "/home/agent/workspace"
}

cell is_secret_name : fn(name: str) -> bool
  fuel 20
{
  if name == "SECRET" { ret true }
  if name == "TOKEN" { ret true }
  if name == "KEY" { ret true }
  if name == "PASS" { ret true }
  ret false
}

cell decide : fn(input: json) -> decision
  cap fs.Read
  fuel 500_000
{
  let builtin = json.get(input, "$.builtin")
  if builtin == "rm" {
    let target = json.get(input, "$.args[0]")
    let root = workspace_root()
    ret fs.path_under(target, root)
  }
  if builtin == "export" {
    let name = json.get(input, "$.args[0]")
    ret !is_secret_name(name)
  }
  ret true
}
