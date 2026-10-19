# call laws: T010 T011 T012 T021
cell add : fn(a: u64, b: u64) -> u64
  fuel 10
{
  ret a + b
}

cell caller : fn(x: u64) -> u64
  fuel 100
{
  let a = missing(x)
  let b = add(x)
  let c = add(x, 1.5)
  let d = x(1)
  ret add(x, x)
}
