cell dirty : fn() -> bool
  fuel 10
{
  ret true
}

policy decide : fn() -> bool
  fuel 10
{
  ret true
}
proof {
  dirty()
}
