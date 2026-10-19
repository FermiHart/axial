# name laws: T001 T002 T003
cell twin : fn() -> ok
  fuel 10
{
  ret ok
}

cell twin : fn() -> ok
  fuel 10
{
  ret ok
}

cell scopes : fn(a: u64) -> u64
  fuel 10
{
  let a = 2
  let b = ghost
  let c = twin
  ret a
}
