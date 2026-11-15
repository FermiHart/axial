# Reference admission policy; does not attest movement or award race rewards.
cell decide : fn(authenticated: bool, exists: bool, entered: bool, racing: bool) -> ok | err.IdentityUnknown | err.NotFound | err.NotEntered | err.NotRacing
  fuel 64
  pure
{
  if !authenticated { ret err.IdentityUnknown }
  if !exists { ret err.NotFound }
  if !entered { ret err.NotEntered }
  if !racing { ret err.NotRacing }
  ret ok
}
