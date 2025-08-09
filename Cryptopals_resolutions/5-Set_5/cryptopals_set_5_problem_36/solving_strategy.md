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

4.  Read the documentation to better understand the problem statement and the requirements: (in progress)

    **Core References & Standards**

    - RFC 2945 – “The SRP Authentication and Key Exchange System” (TBD)
      This is the foundational specification of SRP, describing version 3 of the protocol. It’s the technical standard you’ll want to study closely.
      [IETF Datatracker](https://datatracker.ietf.org/doc/html/rfc2945?utm_source=chatgpt.com)

    - Wikipedia - Secure Remote Password protocol (Done)
      A solid, high-level overview of what SRP is, its advantages (like resisting passive eavesdroppers and not storing password-equivalent data on the server), and its evolution including SRP-6a and real-world deployments.
      [Wikipedia](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol?utm_source=chatgpt.com)

    **Tutorials & Blog Posts**

    - Medium article: “What is Secure Remote Password” (Done)
      A friendly introduction explaining the core mechanics—registration, verifier, salt, and secure authentication—great for getting a conceptual overview.
      [Medium](https://medium.com/synologyc2/what-is-secure-remote-password-12b376f6b119)

    - Medium post: “Secure Remote Password (SRP)” by Cloud Security (TBD)
      Offers a clearer breakdown of the nuances in SRP, common implementation pitfalls, and versioning confusion. Especially helpful if you're planning to implement or audit SRP.
      [Medium](https://medium.com/cloud-security/secure-remote-password-spa-0f91a620ebca)

    **Academic & Technical Papers**

    - Thomas Wu’s original SRP paper (TBD)
      Authored by SRP’s creator, this paper presents the theoretical foundations, security properties, and rationale behind SRP. A must-read for understanding why SRP was designed the way it is.
      [NDSS Symposium](https://www.ndss-symposium.org/wp-content/uploads/2017/09/The-Secure-Remote-Password-Protocol.pdf?utm_source=chatgpt.com)

    - “Formal Methods Analysis of the Secure Remote Password Protocol” (TBD)
      A modern, formal verification of SRP version 3 (the original specification). It looks for structural weaknesses and verifies many security properties, but also notes a subtle attack where a malicious server could impersonate the client under some conditions.
      [arXiv](https://arxiv.org/pdf/2003.07421)

    **Real-World Deployments & Implementations**

    - 1Password's “How We Use SRP” (in progress)
      A practical and insightful example of how a production service leverages SRP. Covers enrollment, verification, and secure session key derivation.
      [1Password Blog](https://blog.1password.com/developers-how-we-use-srp-and-you-can-too/?utm_source=chatgpt.com)

    - Python implementation: pysrp (TBD)
      A well-maintained SRP library in Python. Good for hands-on experimentation or prototyping, compatible with RFC 5054.
      [GitHub](https://github.com/cocagne/pysrp?utm_source=chatgpt.com)

      Reading path:

      1. Wikipedia (Done)
      2. Medium article: “What is Secure Remote Password” (Done)
      3. 1Password blog: “How We Use SRP” (Done)
      4. RFC 2945 (in progress, topic 3)
      5. Thomas Wu’s original SRP paper (TBD)
      6. Formal Methods Analysis of SRP (TBD)
      7. pysrp GitHub repository (TBD)

5.  Understand the problem statement in more detail (TBD)
