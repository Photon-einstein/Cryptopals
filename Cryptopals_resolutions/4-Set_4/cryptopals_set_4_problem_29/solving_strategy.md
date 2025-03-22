**Strategy resolution**

SHA-1 processes input in 512-bit (64-byte) blocks. Before hashing, SHA-1 pads the message using a standard scheme:

Append a 1 bit.
Append 0s until the message length (in bits) is congruent to 448 mod 512 (i.e., leaving space for 64 more bits).
Append the original bit-length of the message as a 64-bit value.

Because SHA-1 lets you continue hashing from an intermediate state (after processing an arbitrary number of bytes), an attacker can:

Guess the key length.
Reconstruct the original padding.
Continue hashing with new data, producing a valid forged MAC.

**Continuing from an Intermediate State**

However, once SHA-1 has processed part of a message, it updates its internal state (a, b, c, d, e).

Since SHA-1 processes data in 512-bit (64-byte) chunks, after hashing the first chunk:

The internal state (a, b, c, d, e) changes.
The next chunk is processed using this new state instead of the original fixed constants.
This is what makes length extension attacks possible:

If an attacker knows the SHA-1 hash of a message, they can extract the internal state (a, b, c, d, e).
By setting these as the new initial state, they can continue hashing extra data as if it was appended to the original message.

**Example: Normal vs. Length Extension**

Let's assume SHA-1 is hashing "hello":  

Normal SHA-1 Process  

Start with the fixed constants (a, b, c, d, e).  
Process "hello".  
Output: SHA1("hello") = 2cf24dba....
Length Extension Attack

Attacker knows SHA1("hello") but not the secret key.
They extract the internal state after processing "hello".
They use this state to continue hashing " world!".
Result: A valid SHA-1 hash for "hello<glue-padding>world!".

**Steps to Implement**

0. **Extraction of the data from the attacker**
    * Setup of the key for the server locally    (Done)
    * Setup of the key for the server remotely  (Done)
    * Extraction of the URL, message and mac from the message intercepted (Done)

1. **Implement SHA-1 Padding**

    * Write a function to compute SHA-1 padding for an arbitrary message. (Done)
    * Verify it against a real SHA-1 implementation. (Done)

2. **Modify SHA-1 to Accept a Custom State**

    * Normally, SHA-1 starts with magic constants in its registers.
    * Modify your SHA-1 implementation to accept arbitrary register values so you can continue hashing. (Done)

3. **Perform the Length Extension Attack**

    * Try different key lengths. (TBD)
    Idea: The idea is that the attacker will append a dummy data to the message,   
    simulating the addition of the key at the server side, after that he will add   
    the padding to the message, and send the message to be tested in at the server.  

    Attacker's Process  
        1. Guess key_length = 16  
        2. Compute SHA-1 padding for "user=bob&amount=1000&timestamp=1700000000" as if it were preceded by 16 bytes
        of a secret key.
        3. Append &isAdmin=true to escalate privileges.  
        4. Compute the new MAC using SHA-1’s state from the intercepted message.  
        Send:

        ```bash
        https://api.example.com/data?user=bob&amount=1000&timestamp=1700000000<PADDING>&isAdmin=true&mac=new_mac_here  
        If the server accepts it, the attack succeeds. If not, try another key_length.  
        ```

    * Attacker tests the server that he has guessed the right key length (Done)
    * Compute the glue padding for key || message. (Done)
    * Use your modified SHA-1 to hash the additional ";admin=true" data. (Done)
    * The result is a valid SHA-1 MAC for the forged message, the attacker can then test the response from the server. (Done)
 
This is why HMAC (H(key || message)) prevents this attack because the key is mixed inside the compression function, 
making it impossible to extend


**Example of a URL**

```bash
https://api.example.com/data?user=bob&amount=1000&timestamp=1700000000&mac=b240077242795755b85fa52c89c9806e0d68c277
```

```bash
mac = SHA1(key || "user=bob&amount=1000&timestamp=1700000000")
```


