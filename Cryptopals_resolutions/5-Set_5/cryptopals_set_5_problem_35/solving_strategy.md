1.  Ports of the servers running in this program (Done)
    Port of Mallory 18080 (production)
    Port of Mallory 18081 (test)

    Port of Server 18082 (production)
    Port of Server 18083 (test)

2.  Add Mallory server code as a copy of the real server, adapting the port numbers (Done)
    2.1.1. Test root endpoint of Mallory server (Done)
    Endpoint URL:
    On the browser:

    ````bash
    http://localhost:18080/

            ```

    2.1.2. Test sessionsData endpoint of Mallory server (Done)
    Endpoint URL:
    On the browser:
    `bash
        http://localhost:18080/sessionsData
        `

    2.2.1. Test root endpoint of real server (Done)
    Endpoint URL:
    On the browser:
    `bash
        http://localhost:18082/
        `

    2.2.2. Test sessionsData endpoint of Mallory server (Done)
    Endpoint URL:
    On the browser:
    `bash
        http://localhost:18082/sessionsData
        `
    ````

3.  Create UML sequence diagram with a .svg output (Done)

    - To generate the sequence diagram in .svg format, run this command at the 'uml_diagrams' folder:

    ```bash
    java -jar /home/tiago-sousa/.vscode/extensions/jebbs.plantuml-2.18.1/plantuml.jar -tsvg sequence_diagram.puml
    ```

4.  Regenerate base uml diagrams with names updated (Done)

5.  Understand the impact when the g parameter is changed for the following parameters: (Done)

    - g = 1
    - g = p
    - g = p - 1

    Study of the impact on the secret key material, based on the change of the g parameter value:

    K = g^(ab) mod p

    7.1. If g = 1:
    A = g^a (mod p) = 1^a (mod p) = 1
    K = A^b (mod p) = 1^b (mod p) = 1

         → K = 1

    7.2. If g = p:
    A = g^a (mod p) = p^a (mod p) = 0
    K = A^b (mod p) = 0^b (mod p) = 0

        → K = 0

    7.3. If g = p-1:
    A = g^a (mod p) = (p-1)^a (mod p) = (-1)^a (mod p) = +/- 1 dependent on the parity of 'a'
    K = A^b (mod p) = (+/-1)^b (mod p) = +/- 1 dependent on the parity of 'a' and 'b'

        → K = +/-1

6.  Read the documentation about this attack: (Done)

[Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice](https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf) (Done)

[The problem of popular primes: Logjam](https://arxiv.org/pdf/1602.02396) (Done)

[LogJam Attack - Computerphile](https://www.youtube.com/watch?v=gVtjsd00fWo&t=7s) (Done)

[RFC-2409 - The internet key exchange](https://datatracker.ietf.org/doc/html/rfc2409) (Done)

7.  Study the best way to allow the attacker to make this changes (Done)
    The server should be allowed to receive a group name, or if no group name is received, then it must receive the value of
    the 'p' and 'g' in the clear. If no values are received at all then it should be an error.

8.  Add extra parameters 'p' and 'g' in the client, they should be extra to the already existing solution of the rfc3526-group-<xy> (Done)
    Requirements: it should not break the existing tests in place.
    For now these fields can be empty.

    Clients should send 'p' and 'g' values instead of group names.
    MitM attack should be able to swap these values instead of dealing with group names.

    Message from Client to Server should have 'p' and 'g' values in the JSON message.
    Response from Server to Client should have also 'p' and 'g'g values instead of the group
    name in the JSON message.

    8.1. Add a new client constructor without group name field (Done)
    8.2. Add a new DiffieHellman constructor without group name field and with p and g hard coded instead (Done)

9.  Rerun build of source code, should compile (Done)
10. Rerun the existing tests, all should pass (Done)
11. Fix the broken build (Done)
12. Fix the broken tests (Done)
13. Create an enum class inside the attacker class (Done)
14. Remove the code from the parameter injection of the last exercise (Done)

15. Double check in the code if all the source code comments have the right documentation  
    regarding the parameters, the documentation of all the methods, the const flag, and  
    the errors throw if applicable. (Done).

        - Client.hpp/cpp (Done);
        - DHParametersLoader.hpp/cpp (Done)
        - DiffieHellman.hpp/cpp (Done)
        - EncryptionUtility.hpp/cpp (Done)
        - MalloryServer.hpp/cpp (Done)
        - MallorySessionData.hpp/cpp (Done)
        - MessageExtractionFacility.hpp/cpp (Done)
        - Server.hpp/cpp (Done)
        - SessionData.hpp (Done)

16. Implement the code to perform the g parameter substitution (Done)
    16.1. Implement the boiler code to perform the substitutions on the g parameter (Done).
    16.2. Implement the code to set the attack strategy in the Mallory server, to allow in this way
    to test all the scenarios (Done)

    16.3. Implement the substitution of g = 1 on the first and second leg of the MitM attack (Done).
    16.4. Implement the test for the g = 1 substitution on the MitM attack (Done).

    16.5. Implement the substitution of g = p on the first and second leg of the MitM attack (Done).
    16.6. Implement the test for the g = p substitution on the MitM attack (Done).
    16.7. Implement the substitution of g = p-1 on the first and second leg of the MitM attack (Done).
    16.8. Implement the test for the g = p-1 substitution on the MitM attack (Done).

17. Run and fix locally the errors detected with the code static analysis (Done)

18. Update the class diagram with the new code of this problem (Done)
    Class status:

    - Server.hpp/cpp (Done)
    - MalloryServer.hpp/cpp (Done)
    - Client.hpp/cpp (Done)
    - SessionData.hpp (Done)
    - MallorySessionData.hpp/cpp (Done)
    - DiffieHellman.hpp/cpp (Done)
    - MessageExtractionFacility.hpp/cpp (Done)
    - EncryptionUtility.hpp/cpp (Done)
    - DhParametersLoader.hpp/cpp (Done)

```bash
java -jar /home/tiago-sousa/.vscode/extensions/jebbs.plantuml-2.18.1/plantuml.jar -tsvg class_diagram.puml
```

19. Update the sequence diagram with the new code of this problem (Done)

```bash
java -jar /home/tiago-sousa/.vscode/extensions/jebbs.plantuml-2.18.1/plantuml.jar -tsvg sequence_diagram.puml
```

20. Replace all PNG's images by SVG ones (Done)
    20.1. Generate SVG to all current projects (Done)

    - problem 28 (Done)
    - problem 29 (Done)
    - problem 30 (Done)
    - problem 31_32 (Done)
    - problem 33 (Done)

      20.2. Generate a new link to the right SVG file (Done)

      - problem 28 (Done)
      - problem 29 (Done)
      - problem 30 (Done)
      - problem 31_32 (Done)
      - problem 33 (Done)

        20.3. Removal of .png uml diagrams from the past articles (in progress)

      - problem 28 (Done)
      - problem 29 (Done)
      - problem 30 (Done)
      - problem 31_32 (Done)
      - problem 33 (Done)

21. Write article about this project (in progress)
    21.1. Introduction (Done)
    21.2. What are the values negotiated via the RFC 3526 ? (Done)
    21.3. What are the possible parameter manipulations (Done)
    21.4. Review and re-format text (Done)
    21.5. Talk about the present code solution, and the changes that were made to the previous
    MitM attack (Done)
    21.6. Include and talk about the class diagram and the main changes in this present diagram (Done)
    21.7. Include and talk about the sequence diagram and the main changes in this present diagram (Done)
    21.8. Include the main results for each manipulation: g = 1, g = p, g = p-1 (Done)

    - Extraction results for g = 1 (Done)
    - Extraction results for g = p (Done)
    - Extraction results for g = p-1 (Done)

    - Talk about the results for g = 1 (Done)
    - Talk about the results for g = p (Done)
    - Talk about the results for g = p-1 (Done)

      21.9. Include a quick demo for the substitution g = 1 (Done)
      21.10. How to protect against this attack, and best practices (Done)
      21.11. Review the entire project (Done)
      21.12. Upload the article into Dev community as well (in progress)
