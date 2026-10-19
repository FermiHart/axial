.eff crypto.Hash

cell test_crypto_hash nregs=3
  contract 1
    ret str
    cap crypto.Hash
    fuel 102
  endcontract
  k0 str "sha256|test data"
  ldk r0 k0
  eff r0 @crypto.Hash r0
  ret r0
end
