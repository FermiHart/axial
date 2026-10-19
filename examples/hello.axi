cell hello : fn(a: u64, b: u64) -> u64
  fuel 10_000
  pure
{
  let n = a + b
  ret n
}
