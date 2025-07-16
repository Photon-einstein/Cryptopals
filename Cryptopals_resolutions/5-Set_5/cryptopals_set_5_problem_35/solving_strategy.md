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

8.  Add extra parameters 'p' and 'g' in the client, they should be extra to the already existing solution of the rfc3526-group-<xy> (in progress)
    Requirements: it should not break the existing tests in place.
    For now these fields can be empty.

    Clients should send 'p' and 'g' values instead of group names.
    MitM attack should be able to swap these values instead of dealing with group names.

    Message from Client to Server should have 'p' and 'g' values in the json message.
    Response from Server to Client should have also 'p' and 'g'g values instead of the group
    name in the json message.

    8.1. Add a new client constructor without group name field (Done)
    8.2. Add a new DiffieHellman constructor without group name field and with p and g hardcoded instead (Done)

9.  Rerun build of source code, should compile (Done)

10. Rerun the existing tests, all should pass (Done)

11. Implement the swapping values, make it adjustable (in progress)
