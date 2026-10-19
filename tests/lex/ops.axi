# operator & literal coverage — lexer does not parse, shape is free
cell t : fn(a: f64, b: u64) -> bool
  fuel 100
  pure
{
  let x = 3.5
  let y = 7_000
  let s = "esc \" \\ \n \t ok"
  let k = [1, 2, 3]
  ret a >= 1.0 != false == true
  ret b <= 2 < 3 > 1
  ret !x | x * y / y % 2 - 1 + 0
  ret k[0] , . ? =
}
