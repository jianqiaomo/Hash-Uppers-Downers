# FE-CTF 2022: Hash Uppers Downers Solution Writeup

Challenge: https://play.fe-ctf.dk/challenges#15-Hash%20Uppers%20Downers 

or https://ctftime.org/task/23758

In this challenge we are given a customized sha-1 code and the remote server interaction.
It turns out that if we enter the correct password we will get the flag.

```angular2html
.
├── Makefile
├── Readme.md
├── hash-uppers-downers
│   ├── server.c       
│   ├── sha1.c
│   └── sha1.h
├── main.cpp
└── progressbar.hpp
```

# Server interaction

We are given the `server.c`. 
It is clear that the server compares the hash digest of our input password and its real password `goodhash`.

```C
if (password[strlen(password)-1] == '\n') password[strlen(password)-1] = '\0';
if (password[strlen(password)-1] == '\r') password[strlen(password)-1] = '\0';

SHA1_Init(&ctx);
SHA1_Update(&ctx, salt, strlen(salt));
SHA1_Update(&ctx, password, strlen(password));
SHA1_Final(&ctx, userhash);

n = memcmp(userhash, goodhash, sizeof(goodhash));

if (n < 0) {
    printf("<\n");
    fflush(stdout);
} else if (n > 0) {
    printf(">\n");
    fflush(stdout);
} else {
    puts(FLAG);
    return EXIT_SUCCESS;
}
```

If the hash of our password matches the correct, it will return the flag. 

Otherwise, it returns the comparison result (`>` or `<`).

# Evaluate possible solutions

There are some common [hash attacks](https://ctf-wiki.mahaloz.re/crypto/hash/attack/). 
We would evaluate their practicability and pick the easiest one to implement. 

### Hash algorithm incorrectly designed

While reviewing the `sha1.c`, we find that the initial states of SHA-1 are incorrect.

```C
void
SHA1_Init(SHA1_CTX *ctx)
{
    /* SHA1 initialization constants */
    ctx->s[0] = 0x67452301;
    ctx->s[1] = 0xEFCDA8B9;
    ctx->s[2] = 0x98BADCFE;
    ctx->s[3] = 0x10325476;
    ctx->s[4] = 0xC3D2E1F0;
    ctx->c[0] = ctx->c[1] = 0;
}
```

The second state `s[1]` should be `0xEFCDAB89` instead of `0xEFCDA8B9` 
([reference](https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode)).

If we can reverse the incorrect SHA1 hash function, we can implement a binary search to the correct password.
We start searching in hash digest range `0x00000000000000000000` ~ `0xFFFFFFFFFFFFFFFFFFFF`.

Then we try the middle point:
`password payload = hash_rev(0x7FFFFFFFFFFFFFFFFFFF)`, send it to the server.

By comparing to the server, if the password payload return a `>`, 
i.e., the `hash(payload)` is larger than the `hash(real password)` (the `goodhash`),
then we can set a new hash digest range `0x00000000000000000000` ~ `0x7FFFFFFFFFFFFFFFFFFF`.

**Irreversible**:
However, further evaluation shows that this idea is _very hard to implement_, because 
the other parts of the SHA1 is correct. 
It still contains 80 rounds operations, 
which is very hard to find a reverse function from a slight difference in the initial state `s[1]`. 

### Common tools

There are some common tools such as [HashCat](https://hashcat.net/hashcat/),
[HashPump](https://github.com/bwall/HashPump).
However, since the SHA1 we are given is different from the original SHA1, 
I **do not** think it is a good option to use or re-implement these tools.

### Collision

SHA1 is no longer safe, because Google has previously published two pdfs with the same sha1 value, please refer to [Shattered](https://shattered.io/).

As our goal is to find the correct password (we don't know the real password target), 
I think collision may **not** be a good way to attack.


### Brute force

We find the length of the real password is 5 and 
restricted to 62 characters library.

```C
char x[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789";
    
assert(strlen(PASSWORD) <= 5);
```

Hence, there are only 62^5 = 916,132,832 possibilities. 
It seems to be a quite small number, but as the server needs more than
1 second to reply a request,

```C
for (;;) {
    sleep(1);
    // ...
}
```

the worst case will require 916,132,832 second (29 years).

### Better brute force and binary search

We find that the random salt for hash is **fixed**,
because the `rand()` use the process pid as seed.
Every time we log in to the server, the salt is a fixed string.

Therefore, we can implement a binary search with the compare result 
from server.
If we can generate hash digests for all password possibilities, sort 
them by their digests, then we can find the correct password by binary search.

```python
password_a = '.....'
# ......
password_z = '.....'

sorted_payload = {
    password_a: hash(password_a),  # lower bound
    # ......
    password_z: hash(password_z)   # upper bound
}
```

SHA-1 is fast, with [~587.9](https://automationrhapsody.com/md5-sha-1-sha-256-sha-512-speed-performance/) ms per 1M operations, thus 
it is practical to prepare all of them.
However, it would take a huge storage cost. Each password and its hash digest need 6 + 20 = 26 Bytes, totally 
916,132,832 * 26 Byte = 22 GB.

# Our solution

As saving all 916,132,832 possibilities is hard, we break the entire task to smaller separations.
We set the first 3 digits in the password fixed and only the lower 2 digits of the passwords are sweep in password 
library. 
Thus, there are only 62^2 = 3844 in each round, and totally 62^3 = 238328 rounds.

We follow these steps in each round:
1. Prepare 3844 passwords. If `hash(password)` is out-of-range, drop it. 
2. Sorted the passwords from low to high of their digest.
3. Send them to server for binary search, update the hash digest range. Start a new round.

## How to run

Build the program in `main.cpp`.

```
$ make
```

We can also evaluate the performance.

```
$ ./main.exe
== proof-of-work: disabled ==
Salt: pkDHTxmMR18N2l9
Password: 
* Your salt           = pkDHTxmMR18N2l9
[#######################################           ] 79%
flag{My h34rt fe3ls l1ke an alligator!}

* Real Password       = kw1Ux
* Time cost           = 451s
# Server call         = 57
# Local hash prepare  = 3876
```

Therefore we find the `flag`. 

The result shows that we call 57 times to the server.
Totally only 3876 hash digests are saved and used, which means we find a small hash digest range and most of the other
passwords are out-of-range (dropped).

# Acknowledgement

https://github.com/gipert/progressbar

https://ctf-wiki.mahaloz.re/