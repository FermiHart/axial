# union laws: T005 T006 T013 T014 T015 T016 T017 T018
cell weird : fn() -> u64 | f64 | ok | ok
  fuel 10
{
  ret 1
}

cell may : fn() -> u64 | err.Io
  fuel 10
{
  ret err.Nope
}

cell leak : fn() -> u64
  fuel 10
{
  let v = may()
  let w = 3?
  let z = may()?
  ret true
}

cell fall : fn() -> u64
  fuel 10
{
  let a = 1
}
