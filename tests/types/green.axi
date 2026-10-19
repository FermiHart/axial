# W06 green: opt, result, err atom, ?, i64 negation, cap opacity, purity
cell double : fn(x: u64) -> u64
  fuel 100
  pure
{
  ret x * 2
}

cell pick : fn(x: u64) -> u64 | ok
  fuel 100
  pure
{
  if x > 10 {
    ret x
  }
  ret ok
}

cell half : fn(x: u64) -> u64 | err.Odd
  fuel 100
  pure
{
  if x % 2 == 1 {
    ret err.Odd
  }
  ret x / 2
}

cell run : fn(x: u64, out: cap io.Write) -> u64 | ok | err.Odd
  fuel 1_000
{
  let h = half(x)?
  let p = pick(h)?
  let d = double(p)
  out.write("result")
  let neg = -5
  let n2 = neg + -1
  ret d
}
