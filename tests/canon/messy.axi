cell add : fn(a: u64, b: u64) -> u64
  fuel 10_000
  pure
{
    let x=a+b
  ret (x)
}