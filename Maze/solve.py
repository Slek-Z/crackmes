
# Maze rules
pattern = "\x8A\x07\x48\xFF\xC7\x3C\x0A\x74\x5E\x2C\x30\x3C\x01\x75\x0E\x48\xC7\xC3\xFF\xFF\xFF\xFF\xB9\x65\x00\x00\x00\xEB\x32\x3C\x02\x75\x0E\x48\xC7\xC3\xFF\xFF\xFF\xFF\xB9\x01\x00\x00\x00\xEB\x20\x3C\x03\x75\x0C\xBB\x01\x00\x00\x00\xB9\x01\x00\x00\x00\xEB\x10\x3C\x04\x75\x24\xBB\x01\x00\x00\x00\xB9\x65\x00\x00\x00\xEB\x00\x48\x0F\xAF\xD9\x48\x6B\xDB\x6A\x48\x8D\x05\xF9\xFF\xFF\xFF\x48\x83\xE8\x57\x48\x01\xD8\xFF\xE0\x31\xC0\xC3" # 106 bytes
dead_end  = "\x31\xC0\xC3" # 3 bytes

start = 0x0716D0
exit = 0x0CB2C8

lower_bound = 0x00013B
upper_bound = 0x1080A8

# Load maze
maze = open("maze", 'rb').read()

# Initialize
visited = {start}
bfs = [(start, "")] # [(int addr, str path), (int addr, str path), ...]
while bfs:
  # Process node
  (addr, path) = bfs.pop(0)
  
  # Target reached?
  if addr == exit:
    print("Solution:\n%s" % (path))
    break
  
  # Bounds check
  if addr < lower_bound or addr > upper_bound:
    continue
  
  # Dead end check
  if maze[addr:addr+len(dead_end)] == dead_end:
    continue
  
  # Check if code follows the pattern...
  if maze[addr:addr+len(pattern)] != pattern:
    print("New code block at %s!" % (hex(addr)))
    break
  
  # Append next nodes BFS
  for (delta, command) in [(-0x29D2, "1"), (-0x006A, "2"), (0x006A, "3"), (0x29D2, "4")]:
    next_addr = addr + delta
    if next_addr not in visited:
      visited.add(next_addr)
      bfs.append((next_addr, path + command))
