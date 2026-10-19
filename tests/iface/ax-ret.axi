# axial iface fixture — v1 contract (Bear Core)
cell fetch : fn(id: i64, out: cap io.Write) -> i64 | err.Io
  fuel 10_000
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
