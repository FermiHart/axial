# zero coercion laws: T007 T008 T009
cell f : fn(a: u64, b: f64, c: bool) -> u64
  fuel 100
{
  let m = a + b
  let r = b % 2.0
  let n = -a
  let k = !a
  if a {
    ret a
  }
  ret a
}
