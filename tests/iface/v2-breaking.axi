# v2: every kind of promise broken at once
cell fetch : fn(id: u64) -> u64 | err.Io
  fuel 10_000
{
  ret id
}
