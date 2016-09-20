import sys
import string
import random

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


fname = sys.argv[1]
n = int(sys.argv[2])

with open(fname, 'w') as f:
    for i in range(n):
        f.write('%s\n' %id_generator(128))