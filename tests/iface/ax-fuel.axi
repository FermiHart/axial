# axial iface fixture — v1 contract (Bear Core)
cell fetch : fn(id: u64, out: cap io.Write) -> u64 | err.Io
  fuel 20_000
{
  out.write("x")
  ret id
}

cell add : fn(a: i64, b: i64) -> i64
  fuel 1000
  pure
{
  ret a + b
}
