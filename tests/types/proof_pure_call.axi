cell clean : fn() -> bool
  fuel 10
  pure
{
  ret true
}

policy decide : fn() -> bool
  fuel 10
{
  ret true
}
proof {
  clean()
}
