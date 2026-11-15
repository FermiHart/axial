cell calculate : fn(a: i64, b: i64) -> i64
  fuel 64
  pure
{
  if a < b { ret a }
  ret b
}
