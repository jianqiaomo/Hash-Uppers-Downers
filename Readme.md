# Hash Uppers Downers Solution Writeup

Challenge: https://play.fe-ctf.dk/challenges#15-Hash%20Uppers%20Downers or https://ctftime.org/task/23758

In this challenge we are given a customized sha-1 code and the remote server interaction.
It turns out that if we enter the correct password we will get the flag.

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

If the hash of our password matches, it will return the flag. 
Otherwise, 


# The encryption function

From the above we can see that the `add` function just xors the current block
with the key.
The `mul` functions does something more complicated, that however does not
depend on the key, just the current block and a constant. Looking at how the
parameters are shifted in the `mul` function (i.e. if one parameter has a bit
set at index `i` and the other at index `j`, then something happens at index
`i+j`) we can see that this seems to do some kind of multiplication, where xor
is used instead of addition.

Note that a bit can be considered an element in the field with two elements `𝔽₂`,
and addition in this field is exactly xor. Similarly, lists of bits can
be considered as elements of `𝔽₂[x]`, and addition in this polynomial ring
corresponds exactly to bitwise xor.
The way one can convert back and forth between such polynomials and natural numbers
is via the bijection given by evaluation at `2`.
```
φ: 𝔽₂[x] -> ℕ
φ: f ↦ f(2)
```

If we now indeed interpret the block that we are encrypting as an element of
𝔽₂[x], then the function `add` is indeed just given by addition with the key.
Furthermore, if `ulong` types had infinite width and we removed the lines
```C
    if (bVar1) {
      bigger_param = bigger_param ^ R;
    }
```
from the code, then the `mul` function would just be multiplication with
`φ^{-1}(0x1337)`.
What the three lines above do is dealing with bits that can not be represented
due to the highest indexed bit being the one indexed by `63`. Concretely,
a set bit indexed by `64` is folded back into the block by adding
the constant `R=0x1b`. This corresponds to carrying out the multiplication
in the quotient ring `S = 𝔽₂[x]/(x^64 - φ^{-1}(0x1b))`.
If we write `c = φ^{-1}(0x1b)`, `m = φ^{-1}(0x1337)`, and `k = φ^{-1}(key)`,
then we can interpret the single encryption round `enc1` as a function
from `S` to `S` mapping `a` to `m*(a+k) = m*a + m*k`.


# The weakness

What happens if we apply `enc1` multiple times? If we apply it twice we
will map `a` to `m*(m*a + m*k) + m*k = m^2*a + (m^2*k + m*k)`.
By induction one can easily prove that `enc1^n` maps `a` to
`m^n + (m^n*k + m^{n-1}*k + ... + m^2*k + m*k)`.

If we write `K = m^1000000*k + ... + m*k`, then this implies that the encryption
function maps `a` to `m^1000000*a + K`, where `m` is known.
If we know a single cleartext-ciphertext-pair `(a, m^1000000*a + K)`
we will thus be able to recover `K` as `K = (m^1000000*a + K) - m^1000000*a`.
We can then decrypt arbitrary encrypted blocks by subtracting `K` and
dividing by `m^1000000`.


# The solution

To obtain `K` we send a number `a` (it doesn't matter which one, but testing that
we get the same result for different ones is a good way to check that our
analysis was correct) and recover `K` using the calculation just described:
```python
s = pwnlib.tubes.remote.remote(HOST, PORT)
to_send = p64(a, endian="little")
s.send(to_send)
s.shutdown("write")
data = s.recv()
enc_a = u64(data, endian="little")
a_part = mul(a, power(mul_const, rounds))
key_part = add(a_part, enc_a)
```
The variable `mul_const` here is what was called `m` so far and
`rounds=1000000`.  Note that addition in subtraction is the same in 𝔽₂.
Finally, the reason `s.shutdown("write")` is called is because `magic` will
only output an answer after `stdin` has been closed, so when interacting with
the remote we have to close the connection in the send direction. I had a
little trouble with how to do this, but luckily an organizer helped me.

After we have obtained `K`, we still have to figure out how to divide by
`m^1000000` in order to be able to decrypt. For this we need to obtain
the multiplicative inverse of `m` in `𝔽₂[x]/(x^64 - φ^{-1}(0x1b))`.

For this we use sage:
```python
$ sage
┌────────────────────────────────────────────────────────────────────┐
│ SageMath version 9.5, Release Date: 2022-01-30                     │
│ Using Python 3.10.8. Type "help()" for help.                       │
└────────────────────────────────────────────────────────────────────┘
sage: F = FiniteField(2)
sage: P = F[x]
sage: C = 1 + x + x**3 + x**4
sage: S = P.quotient(x**64 - C)
sage: xbar = S.gen()
sage: n = 0x1337
sage: i = 0
sage: m = 0
sage: while n > 0:
....:     if n & 1:
....:         m += xbar^(i)
....:     n = n >> 1
....:     i += 1
....: 
sage: m^(-1)
xbar^58 + xbar^55 + xbar^53 + xbar^52 + xbar^48 + xbar^44 + xbar^40 + xbar^38 + xbar^37 + xbar^36 + xbar^35 + xbar^34 + xbar^31 + xbar^29 + xbar^28 + xbar^27 + xbar^26 + xbar^25 + xbar^23 + xbar^19 + xbar^16 + xbar^15 + xbar^13 + xbar^11 + xbar^10 + xbar^9 + xbar^4 + xbar^2 + 1
```
Setting `xbar = 2` and evaluating the last expression we obtain the natural
number corresponding to `m^(-1)`.

Now the flag can be decrypted as follows:
```python
xbar = 2
mul_const_inv = xbar**58 + xbar**55 + xbar**53 + xbar**52 + xbar**48 + xbar**44 + xbar**40 + xbar**38 + xbar**37 + xbar**36 + xbar**35 + xbar**34 + xbar**31 + xbar**29 + xbar**28 + xbar**27 + xbar**26 + xbar**25 + xbar**23 + xbar**19 + xbar**16 + xbar**15 + xbar**13 + xbar**11 + xbar**10 + xbar**9 + xbar**4 + xbar**2 + 1
mul_const_inv_power_rounds = power(mul_const_inv, rounds)

with open("flag.enc", "rb") as fh:
    ciphertext = fh.read()

flag = b''
for i in range(0, len(ciphertext), 8):
    ciphertext_block = ciphertext[i:i+8]
    ciphertext_block_number = u64(ciphertext_block)
    no_key_part = add(ciphertext_block_number, key_part)
    cleartext_number = mul(no_key_part, mul_const_inv_power_rounds)
    cleartext = p64(cleartext_number)
    flag += cleartext
```

The flag is appropriately `flag{90% of crypto: division is hard}` :). 

The file `solve.py` contains my solution script exactly as I used it during the CTF.