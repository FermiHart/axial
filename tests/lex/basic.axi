# axial lex smoke — canonical cell shape (Bear Core)
cell fib : fn(n: u64) -> u64
  fuel 1_000_000
  pure
{
  if n < 2 { ret n }
  ret fib(n - 1) + fib(n - 2)
}

cell greet : fn(out: cap io.Write) -> ok | err.Io
  fuel 10_000
{
  out.write("beyond> ")?
  ret ok
}
