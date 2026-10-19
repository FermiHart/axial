# same contract, cells in the other order, different bodies/comments
cell add : fn(a: i64, b: i64) -> i64
  fuel 1000
  pure
{
  let s = a + b
  ret s
}

cell fetch : fn(id: u64, out: cap io.Write) -> u64 | err.Io
  fuel 10_000
{
  out.write("x")
  out.write("x")
  ret id
}
