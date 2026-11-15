# Reference game policy: ownership/reservation are authoritative observations.
cell decide : fn(authenticated: bool, exists: bool, owns: bool, unreserved: bool) -> ok | err.IdentityUnknown | err.NotFound | err.NotOwner | err.Reserved
  fuel 64
  pure
{
  if !authenticated { ret err.IdentityUnknown }
  if !exists { ret err.NotFound }
  if !owns { ret err.NotOwner }
  if !unreserved { ret err.Reserved }
  ret ok
}
