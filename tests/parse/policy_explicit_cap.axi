.eff fs.Read
.eff fs.Write

policy decide : fn(input: json) -> bool
  cap fs.Read, fs.Write
  fuel 500_000
{
  ret true
}
