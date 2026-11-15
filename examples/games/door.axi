# Reference game policy: server-derived access facts, no world effects.
cell decide : fn(authenticated: bool, exists: bool, authorized: bool, unlocked: bool) -> ok | err.IdentityUnknown | err.NotFound | err.AccessDenied | err.Locked
  fuel 64
  pure
{
  if !authenticated { ret err.IdentityUnknown }
  if !exists { ret err.NotFound }
  if !authorized { ret err.AccessDenied }
  if !unlocked { ret err.Locked }
  ret ok
}
