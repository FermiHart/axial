# W07 authority laws: T022 T025 T026
cell log : fn(x: u64, out: cap io.Write) -> ok
  fuel 100
{
  out.write(x)
  ret ok
}

cell smuggle : fn(x: u64, net: cap net.Send) -> ok
  fuel 200
{
  log(x, net)
  net.send(net)
  let f = net.send
  let e = net[0]
  ret ok
}

cell hoarder : fn(x: u64, out: cap io.Write) -> u64
  fuel 100
{
  ret x + 1
}
