# Generic typed decision fixture; application rules belong to their consumer.
cell decide : fn(identityKnown: bool, resourceAllowed: bool, available: bool) -> ok | err.IdentityUnknown | err.ResourceDenied | err.Unavailable
  fuel 64
  pure
{
  if !identityKnown { ret err.IdentityUnknown }
  if !resourceAllowed { ret err.ResourceDenied }
  if !available { ret err.Unavailable }
  ret ok
}
