# purity + collections: T019 T020
cell dirty : fn() -> ok
  fuel 10
{
  ret ok
}

cell holy : fn(out: cap io.Write) -> ok
  fuel 10
  pure
{
  dirty()
  out.write(1)
  let l = [1, 2]
  ret ok
}
