#! /usr/bin/python3
import re
f = open("01.msg", "r")
words = re.sub("[^\w]", " ", f.read()).split()
for word in words:
    for c in word:
        print("c = ", c, " | ord(c) = ", ord(c))
