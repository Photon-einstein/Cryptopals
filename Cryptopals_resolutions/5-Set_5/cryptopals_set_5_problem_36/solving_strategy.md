1. To test the endpoints run the following URL: (Done)

Endpoint URL:
On the browser:

```bash
http://localhost:18080/<endpoint_name>
```

2.  Migrate the baseline code from the implementation of the Diffie Hellman key exchange protocol,  
    adapting the number of the problem statement, rebuilding the source code and re-running the tests. (Done)

        2.1. Source code should build and run as expected (Done)
        2.2. Tests should build and pass as expected (Done)

3.  Run the problem statement at the Cryptopals website (Done)
    URL link: https://cryptopals.com/sets/5/challenges/36

4.  Read the documentation to better understand the problem statement and the requirements: (Done)

    **Core References & Standards**

    - RFC 2945 – “The SRP Authentication and Key Exchange System” (Done)
      This is the foundational specification of SRP, describing version 3 of the protocol. It’s the technical standard you’ll want to study closely.
      [IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc2945?utm_source=chatgpt.com)

    - Wikipedia - Secure Remote Password protocol (Done)
      A solid, high-level overview of what SRP is, its advantages (like resisting passive eavesdroppers and not storing password-equivalent data on the server), and its evolution including SRP-6a and real-world deployments.
      [Wikipedia](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol?utm_source=chatgpt.com)

    **Tutorials & Blog Posts**

    - Medium article: “What is Secure Remote Password” (Done)
      A friendly introduction explaining the core mechanics—registration, verifier, salt, and secure authentication—great for getting a conceptual overview.
      [Medium](https://medium.com/synologyc2/what-is-secure-remote-password-12b376f6b119)

    **Academic & Technical Papers**

    - Thomas Wu’s original SRP paper (Done)
      Authored by SRP’s creator, this paper presents the theoretical foundations, security properties, and rationale behind SRP. A must-read for understanding why SRP was designed the way it is.
      [NDSS Symposium](https://www.ndss-symposium.org/wp-content/uploads/2017/09/The-Secure-Remote-Password-Protocol.pdf?utm_source=chatgpt.com)

    - “Formal Methods Analysis of the Secure Remote Password Protocol” (Done)
      A modern, formal verification of SRP version 3 (the original specification). It looks for structural weaknesses and verifies many security properties, but also notes a subtle attack where a malicious server could impersonate the client under some conditions.
      [arXiv](https://arxiv.org/pdf/2003.07421)

    **Real-World Deployments & Implementations**

    - 1Password's “How We Use SRP” (Done)
      A practical and insightful example of how a production service leverages SRP. Covers enrollment, verification, and secure session key derivation.
      [1Password Blog](https://blog.1password.com/developers-how-we-use-srp-and-you-can-too/?utm_source=chatgpt.com)

    - Python implementation: pysrp (Done)
      A well-maintained SRP library in Python. Good for hands-on experimentation or prototyping, compatible with RFC 5054.
      [GitHub](https://github.com/cocagne/pysrp?utm_source=chatgpt.com)

    Proposed communication flow present at RFC 2945 pg.5:

            Client                             Host
          --------                           ------
            U                           -->
                                        <--    s, B, group_id
            A, H(H(N) XOR H(g) | H(U) | s | A | B | K) simplified to HMAC-SHA256(K, salt) in this problem
                                        -->
                                        <--    H(A | M | K) simplified to  "OK" if HMAC-SHA256(K, salt) validates

    The values of N and g used in this protocol must be agreed upon by
    the two parties in question. They can be set in advance, or the host
    can supply them to the client. In the latter case, the host should
    send the parameters in the first message along with the salt. For
    maximum security, N should be a safe prime (i.e. a number of the form
    N = 2q + 1, where q is also prime). Also, g should be a generator
    modulo N (see [SRP] for details), which means that for any X where 0
    < X < N, there exists a value x for which g^x % N == X.

    RFC 5054 specifically defines SRP groups and gives them SRP Group IDs.
    These are almost identical to the MODP primes from RFC 3526 (in fact,
    many are the same numbers), but RFC 5054 formalizes their use in SRP
    and provides example parameters for NIST-sized safe primes.

    In RFC 5054 the SRP groups have IDs from 1 to 8.

    Here’s the mapping from the RFC:

    ID Prime Size Origin / Note
    1 1024-bit Safe prime (matches MODP Group 2 from RFC 2409, later RFC 3526)
    2 1536-bit Matches MODP Group 5
    3 2048-bit Matches MODP Group 14
    4 3072-bit Matches MODP Group 15
    5 4096-bit Matches MODP Group 16
    6 6144-bit Matches MODP Group 17
    7 8192-bit Matches MODP Group 18
    8 256-bit NIST P-256 elliptic curve parameters (for SRP-ECC variant)

    The ID 8 is out of scope for this problem, as it refers to the ecliptic
    curve algorithms.

    Reading path:

    1. Wikipedia (Done)
    2. Medium article: “What is Secure Remote Password” (Done)
    3. 1Password blog: “How We Use SRP” (Done)
    4. RFC 2945 (Done)
    5. Thomas Wu’s original SRP paper (Done)
    6. Formal Methods Analysis of SRP (Done)
    7. pysrp GitHub repository (Done)
    8.

5.  Understand the problem statement in more detail (Done)

6.  Clean the code from all the still not needed methods (Done)

    1. Client(.hpp/cpp), trimmed (Done)
    2. Server(.hpp/cpp), trimmed (Done)
    3. DiffieHellman(.hpp/cpp) deleted (Done)
    4. SessionData.hpp, deleted (Done)
    5. runClient2.cpp, deleted (Done)
    6. runClient3.cpp, deleted (Done)
    7. tests/test_diffieHellman.cpp, deleted (Done)
    8. tests/test_diffieHellmanProtocol.cpp, deleted (Done)

7.  Test the root endpoint on the server, it should still work (Done)

    Endpoint URL:
    On the browser:

    ```bash
    http://localhost:18080/
    ```

8.  Run the baseline of the remaining tests, namely the test_dhParametersLoader.cpp,
    it should still work (Done)

9.  Update the baseline code in accordingly to the present problem (Done)

    - renaming all the variables that are currently in the source code, that were pointing to the DH old problem (Done)
    - update the parameters of the json file accordingly to the recommendations present at the
      [RFC 5054](https://datatracker.ietf.org/doc/html/rfc5054) (Done)

10. Update the tests_srpParametersLoader.cpp accordingly to the new specifications (Done)

    - update the source code of the SprParametersLoader(.cpp/.hpp) file with the data extraction (Done)
    - update the tests of the file test_srpParametersLoader.cpp so that they start passing again (Done)

11. Add the SRP parameters loader into the SecureRemotePassword class constructor (Done)

12. Add the map from the session ID to the SecureRemotePassword on the session data (Done)

13. Add the skeleton of the SecureRemotePassword on the Server class (Done)

14. Study the registration information flow that needs to take place before the SRP (Done)

Registration Flow

```text
Client                        Server
  |                              |
  |    Request SRP params (U)    |
  |----------------------------->|
  |                              |
  |   Receive groupId (N, g)     |
  |   and salt (s)               |
  |<-----------------------------|
  |                              |
  | Compute:                     |
  | x = H(s | P)                 |
  | v = g^x mod N                |
  |                              |
  | Send U, v                    |
  |----------------------------->|
  |                              |
  |        OK / Ack              |
  |<-----------------------------|
```

Purpose: Server stores (U, s, v) to authenticate future logins.

No password is sent, only verifier v.

No session key yet.

15. Add the first leg on the client side (Done)

```text
Client                        Server
  |                              |
  |    Request SRP params (U)    |
  |----------------------------->|
```

```json
{
  "username": "alice",
  "requestedGroup": 7 // optional
}
```

16. Add the reception of the first leg on the server side, with the data validations (Done)

17. Update the tests to also test the hash algorithm at the file test_srpParametersLoader.cpp (Done)

18. Format the group input parameters of the past problems so that the long prime hexadecimal number doesn't
    go out of bounds, and adjust the groupParameterLoader tests (Done)

19. Include the hash algorithms SHA-256, SHA384 and SHA512 at the source code (Done)

20. Create tests for each SHA, to ensure that all the wrapper to OpenSSL are working properly (Done):
    20.1. Tests for SHA256 (Done)
    20.2. Tests for SHA284 (Done)
    20.3. Tests for SHA512 (Done)

21. Change the endpoint of the current server to a get group instead, as each endpoint can only have
    one request & response (Done)

22. Add the second leg of the registration process, on the server side, with the proper response
    to the client (Done)
    22.1. Add the request from the client (Done)
    22.2. Add the validation at the server side of the request (Done)
    22.3. Add the response of the server (Done)
    22.4. Add the reception of the message and validation of the data on the client side (Done)
    22.5. Store the required data received on the client side (Done)

```text
Client                        Server
  |                              |
  |    (Request SRP params (U))  |
  |(--------------------------->)|
  |                              |
  |   Receive groupId (N, g)     |
  |   and salt (s)               |
  |<-----------------------------|
  |                              |
```

Example of the kind of response by the given server:

```json
{
  "groupId": 5,
  "groupName": "SRP 4096-bit Group 5",
  "primeN": "...hex...",
  "generatorG": 2,
  "sha": "SHA-256",
  "salt": "A1B2C3D4E5F6" // size of the salt depends on the SHA variant used
}
```

23. Add tests to the SessionData structure (Done)

24. Test manually the endpoint handleRegisterInit endpoint at the server side (Done)

    24.1. Curl with only a userId: (Done)

    ````bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "client123"
          }' | jq

    24.2. Curl with a userId and requestedGroup < default: (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "client123",
            "requestedGroup": 2
          }' | jq
    ````

    24.3. Curl with a userId and requestedGroup = default: (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "client123",
            "requestedGroup": 4
          }' | jq
    ```

    24.4. Curl with a userId and requestedGroup > default: (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "client123",
            "requestedGroup": 6
          }' | jq
    ```

    24.5. Curl with a userId and an invalid groupId, lower bound: (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "client123",
            "requestedGroup": -2
          }' | jq
    ```

    24.6. Curl with a userId and an invalid groupId, upper bound: (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "client123",
            "requestedGroup": 8
          }' | jq
    ```

    24.7. Curl with an empty userId: (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": ""
          }' | jq
    ```

    24.8. Curl with no userId field: (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
          }' | jq
    ```

25. Add tests at the server side (Done)

26. Add tests at the client side (Done)

27. Add tests to the handleRegisterInit endpoint at the server side (Done)

    ```bash
      curl -X POST http://localhost:18080/src/register/init \
      -H "Content-Type: application/json" \
      -d '{
            "clientId": "<client_ID>", // string
            "requestedGroup": <requestedGroup> // optional | unsigned int
          }' | jq
    ```

    27.1. Curl with only a userId: (Done)
    27.2. Curl with a userId and requestedGroup < default: (Done)
    27.3. Curl with a userId and requestedGroup = default: (Done)
    27.4. Curl with a userId and requestedGroup > default: (Done)
    27.5. Curl with a userId and an invalid groupId: (Done)
    27.6. Curl with an empty userId: (Done)
    27.7. Curl with no userId field: (Done)

28. Add tests to the Registration method at the client side (Done)

29. Extract the first leg of the registration to a shared method, and fix the tests if needed (Done)

30. Add the skeleton of the registration process on the client side, the second leg,
    with the following scope:

- handleRegisterComplete() → handles /srp/register/complete (At the server side)

- registrationComplete() (at the client side)

Spec:

```text
Client                        Server
  |                              |
  |    Request SRP params (U)    |
  |----------------------------->|
  |                              |
  |   Receive groupId (N, g)     |
  |   and salt (s)               |
  |<-----------------------------|
TBD bellow:
  |                              |
  | Compute:                     |
  | x = H(s | P)                 |
  | v = g^x mod N                |
  |                              |
  | Send U, v                    |
  |----------------------------->|
  |                              |
  |        OK / Ack              |
  |<-----------------------------|
TBD end:
```

Specifications more information:

- x = H(s | P) computed as raw bytes;
- Password using system-generated (recommended for cryptography testing)
  Generate a random string with high entropy.
  Use a secure PRNG (e.g., OpenSSL RAND_bytes, C++ std::random_device + std::uniform_int_distribution).
  Include alphanumeric + special characters to maximize entropy.

  30.1. Add an auxiliary method to generate a password, minimum size should be 16 bytes (Done)
  30.2. Generate a password at the client side (Done)
  30.3. Generate x = H(s | P) (Done)
  30.4. Generate v = g^x mod N (Done)
  30.5. Add the following leg at the client: (Done)

  ```bash
  | Send U, v                    |
  |----------------------------->|
  ```

30. Add the reception and validation of the user U and the v parameter. (Done)

- U be a new one;
- v should be inside this space (0, N)

  ```bash
  |        OK / Ack              |
  |<-----------------------------|
  ```

31. If U and v are valid then store it inside the new session at the server side (Done)

32. Perform the reception of the server response at the server side (TBD)

33. Perform manual tests of the registration step (TBD).

34. Add unit tests of the registration step (TBD).

35. Add the first leg on server side of the Secure Remote Password protocol (TBD)

36. Add the skeleton of the SecureRemotePassword on the Client class (TBD)

37. Add the first leg on client side of the Secure Remote Password protocol (TBD)
