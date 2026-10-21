/* W78 rich source shared by wire-compatibility tests and matched binaries. */
#ifndef AXI_MANIFEST_FIXTURE_H
#define AXI_MANIFEST_FIXTURE_H
static const char source[] =
    ".eff io.Write\n.eff fs.Read\n"
    "cell zulu : fn(second: u64, first: bool) -> err.Zed | ok | u64 | err.Alpha\n"
    "  fuel 1000\n  pure\n{\n  if first { ret err.Zed }\n  ret second\n}\n"
    "policy alpha : fn(input: json) -> bool\n  fuel 2000\n{ ret true }\n"
    "proof {\n  true\n  2 == 2\n  0.1 == 0.1\n  \"\\t\" == \"\\t\"\n}\n"
    "cell caps : fn(writer: cap io.Write, reader: cap fs.Read, id: u64) -> u64\n"
    "  fuel 100\n{ writer.write(\"x\") reader.read(\"x\") ret id }\n"
    "cell alpha_more : fn(x: f64) -> f64\n  fuel 100\n  pure\n{ ret x }\n";
#endif
