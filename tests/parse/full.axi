# parser coverage: else, list literal, index, try, field, unary, cap, err set
cell pick : fn(xs: bytes, i: u64, w: cap io.Write) -> u64 | err.Range | err.Io
  fuel 5_000
{
  let ys = [1, 2, 3]
  let z = -i + !true
  if i < 3 {
    w.write("small ")?
    ret ys[i]
  } else {
    ret pick(xs, i % 3, w)?
  }
}
