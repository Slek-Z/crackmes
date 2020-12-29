# Maze
## Description

Please try to understand this binary and solve it!

by [jeffli6789](https://crackmes.one/user/jeffli6789)
[5f009fa233c5d42850709479](https://crackmes.one/crackme/5f009fa233c5d42850709479)

## Solution

### Peeking into The Maze

This one can be intimidating at first: it's a 1 MB level 4 crackme written in assambler!

```
$ ls -l --block-size=K
-rwxrwxr-x 1 root root 1057K Jul  4 17:26 maze
```

Grab something to drink and let's get started.

The [maze](maze) executable is a 64-bit console application with no external dependencies:
```
$ file maze 
maze: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

The entry point looks surprisingly simple: just 29 insructions (139 bytes) and a single funciton call. Looking at the disassembled code, we see that it uses [syscall](https://filippo.io/linux-syscall-table/) to perform the standard io operations. We have to make that single function call return a non-zero value if we want to read the congratulations message. It doesn't seem that hard put this way, isn't it?
```
000000b0: ba2e000000                       MOV EDX, 0x2e     ;count
000000b5: 48be1481700000000000             MOV RSI, 0x708114 ;"Welcome to the maze! \nPlease type you input: \n"
000000bf: bf01000000                       MOV EDI, 0x1      ;fd (stdout)
000000c4: b801000000                       MOV EAX, 0x1      ;write
000000c9: 0f05                             SYSCALL
000000cb: b800000000                       MOV EAX, 0x0      ;read
000000d0: bf02000000                       MOV EDI, 0x2      ;fd (stdin)
000000d5: 48be5c81700000000000             MOV RSI, 0x70815c ;buf
000000df: ba10270000                       MOV EDX, 0x2710   ;count
000000e4: 0f05                             SYSCALL
000000e6: 48bf5c81700000000000             MOV RDI, 0x70815c ;buf
000000f0: e8db150700                       CALL 0x716d0
000000f5: 84c0                             TEST AL, AL
000000f7: 741d                             JZ 0x116
000000f9: ba0c000000                       MOV EDX, 0xc      ;count
000000fe: 48be4e81700000000000             MOV RSI, 0x70814e ;"Well done!\n"
00000108: bf01000000                       MOV EDI, 0x1      ;fd (stdout)
0000010d: b801000000                       MOV EAX, 0x1      ;write
00000112: 0f05                             SYSCALL
00000114: eb1b                             JMP 0x131
00000116: ba0c000000                       MOV EDX, 0xc      ;count
0000011b: 48be4281700000000000             MOV RSI, 0x708142 ;"Try again!\n"
00000125: bf01000000                       MOV EDI, 0x1      ;fd (stdout)
0000012a: b801000000                       MOV EAX, 0x1      ;write
0000012f: 0f05                             SYSCALL
00000131: b801000000                       MOV EAX, 0x1
00000136: cd80                             INT 0x80
00000138: 31c0                             XOR EAX, EAX
0000013a: c3                               RET
```

Our journey then starts at 0x0716d0 (where that single call leads us). The function first reads a byte from the input string. Then a switch-case-like pattern follows. The new line character (0x0a) represents the end-of-stream. Only 4 possible values allow us to continue the execution without returning zero: 1, 2, 3, 4 (ascii).
For each value, different constants are loaded into the RBX and RCX registers (+/- 0x1 and +/-0x65, respectively), and the execution flow then converges to 0x07171f. These values are used to compute an offset relative to address 0x0716d0 = 0x071727 - 0x57. One quick note, the `LEA` instruction at address 0x071727 loads its own address into RAX using RIP-relative addressing.
```
000716d0: 8a07                             MOV AL, [RDI]
000716d2: 48ffc7                           INC RDI
000716d5: 3c0a                             CMP AL, 0xa
000716d7: 745e                             JZ 0x71737
000716d9: 2c30                             SUB AL, 0x30
000716db: 3c01                             CMP AL, 0x1
000716dd: 750e                             JNZ 0x716ed
000716df: 48c7c3ffffffff                   MOV RBX, -0x1
000716e6: b965000000                       MOV ECX, 0x65
000716eb: eb32                             JMP 0x7171f
000716ed: 3c02                             CMP AL, 0x2
000716ef: 750e                             JNZ 0x716ff
000716f1: 48c7c3ffffffff                   MOV RBX, -0x1
000716f8: b901000000                       MOV ECX, 0x1
000716fd: eb20                             JMP 0x7171f
000716ff: 3c03                             CMP AL, 0x3
00071701: 750c                             JNZ 0x7170f
00071703: bb01000000                       MOV EBX, 0x1
00071708: b901000000                       MOV ECX, 0x1
0007170d: eb10                             JMP 0x7171f
0007170f: 3c04                             CMP AL, 0x4
00071711: 7524                             JNZ 0x71737
00071713: bb01000000                       MOV EBX, 0x1
00071718: b965000000                       MOV ECX, 0x65
0007171d: eb00                             JMP 0x7171f
0007171f: 480fafd9                         IMUL RBX, RCX
00071723: 486bdb6a                         IMUL RBX, RBX, 0x6a
00071727: 488d05f9ffffff                   LEA RAX, [RIP-0x7]  ;RAX = 0x071727
0007172e: 4883e857                         SUB RAX, 0x57
00071732: 4801d8                           ADD RAX, RBX
00071735: ffe0                             JMP RAX
00071737: 31c0                             XOR EAX, EAX        ;|
00071739: c3                               RET                 ;| return 0;
```

The 4 possible execution paths are then (relative to 0x0716d0):
1: -0x29d2 = -0x1\*0x65\*0x6a
2: -0x6a   = -0x1\*0x1\*0x6a
3: +0x6a   =  0x1\*0x1\*0x6a
4: +0x29d2 =  0x1\*0x65\*0x6a

Looking at the disassembled code from those addresses, they are either a `return 0` or the exact same code above. The next obvious question is: where is the exit (i.e. non-zero retrun)? This starts looking like a *maze*!

At this point I finally understood what was inside jeffli6789's head ;)

### Looking for The Exit

We have a huge (~1 MB) file from where to search the non-zero return. There are a lot of `RET` instructions (actually, all dead ends have one), therefore manually seacrhing for all opcode 0xc3 in the binary and looking at the disassembly would take too long. But we can do it programmatically :D We also don't know how the non-zero value is loaded into the AL register. Guessing the preceding instruction(s) and seaching for the opcodes can do the job, if you are lucky.

However, since I'm usually not very lucky, I decided to write a small [script](targets.py) for this job. The idea is to look at every `RET` instruction and the preceding one. If the previous instruction was not a `XOR EAX,EAX`, we should consider taking a closer look at the code at that address... The output of the python script is:
```
-------------------------------------------
000cb2c8: b801000000                       MOV EAX, 0x1
000cb2cd: c3                               RET
-------------------------------------------
```

We actually found the exit of the maze!

Disassembly powered by [diStorm3](https://github.com/gdabah/distorm).

### Finding The Way Out

The only thing left now is to reach the exit following the maze rules. We can find the shortest path to the exit using a [Breadth-first seach](https://en.wikipedia.org/wiki/Breadth-first_search) approach. This is excatly what the [solve.py](solve.py) does.
```Pyhton
# Maze rules
pattern = "\x8A\x07\x48\xFF\xC7" # 5 bytes
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
```

The lower and upper bounds can be found by looking at the bounds of `return 0` pattern inside the binary. The script just performs a standard BFS while storing the path at each node. In case we find code that doesn't exactly follows the one we analysied, we stop the search and output the address for further analysis. Hopefully the exit address will be reached at some point, and the input string to make that funciton call return a non-zero value will be printed.

```
Solution:
4444221122221111331133334433443344333344334433113333443333113311111111112211113333331122113311221111113333444444444444442244224433442244443333113344442222444433444422442244442244221111224444221111111122111122442211224444443344222222442244224433334422222244333333444444333311331133331111224422111111224422111133333333442244333333333333113311113311331111334433331122113333331122111111221133331122222244444433444422112211111122112211331133443333333333334422443333331133331122113311221111112222113311334433113333111111221111224444221111111111224422443344444444222244222211221122444444333333443344443333442244224422222222221111333333331122112211224422442244442211111133113311222211111111221111331133334433111122112244222244221122111122113333334422443333111133443333113344334422443344443333111122111111333344224433331133331133334433331133444422222222224444443311113333333344444422111122444444334444334444222244222244333344333344222244222244334444442222442222443333442222224422443333444444333344444422224444334433333311113333334444221122444433334444444422444422224422444444444444442211111111222244334444222222442222222211224422221111333333334433331133331111224422221111221111221122221111112244444444444444442211221133111111222211331133111111113333334433442244
```

It turns out that I got lucky this time.

### Conclusions

This is a very creative crackme, where we actually wrote a maze solver in order to get the congratulations message. I enjoyed it 

The dissasembly to find the exit code isn't really necessary. Since the binary has a fixed structure, we could have just searched for 3 patterns (`NOP` opcode, the return 0 sequence and the snipet that performs the `JMP`) and only analyse the parts that don't fit in these patterns.
