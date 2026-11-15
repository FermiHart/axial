# Generic pure permission fixture; application rules belong to their consumer.
cell decide : fn(identityKnown: bool, resourceAllowed: bool, available: bool) -> bool
  fuel 64
  pure
{
  if !identityKnown { ret false }
  if !resourceAllowed { ret false }
  if !available { ret false }
  ret true
}
