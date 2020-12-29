import distorm3

filename = "maze"
offset = 0xb0
length = distorm3.Decode64Bits

code = open(filename, 'rb').read()
code = code[offset:]

prev = None
iterable = distorm3.DecodeGenerator(offset, code, length)
for (offset, size, instruction, hexdump) in iterable:
  if hexdump == "c3" and prev is not None and prev[1] != "31c0":
    print("-------------------------------------------")
    print("%.8x: %-32s %s" % prev)
    print("%.8x: %-32s %s" % (offset, hexdump, instruction))
    print("-------------------------------------------")
  prev = (offset, hexdump, instruction)
