policy decide : fn(input: json) -> bool
  fuel 10
{
  if false {
    ret true
  } else {
    ret 7
  }
  ret false
}
