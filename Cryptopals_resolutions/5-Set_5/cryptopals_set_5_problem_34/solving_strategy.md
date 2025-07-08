1. Explore what is the man in the middle attack (Done)
2. Explore what would need to change to the original setup of the protocol (Done)
    Port of Mallory 18080 (production)
    Port of Mallory 18081 (test)

    Port of Server 18082 (production)
    Port of Server 18083 (test)

3. Add Mallory server code as a copy of the real server, adapting the port numbers (Done)
    3.1.1. Test root endpoint of Mallory server (Done)
            Endpoint URL: 
            On the browser:
            ```bash
            http://localhost:18080/

            ```
    
    3.1.2. Test sessionsData endpoint of Mallory server (Done)
            Endpoint URL: 
            On the browser:
            ```bash
            http://localhost:18080/sessionsData
            ```
    
    3.2.1. Test root endpoint of real server (Done)
            Endpoint URL: 
            On the browser:
            ```bash
            http://localhost:18082/
            ```

    3.2.2. Test sessionsData endpoint of Mallory server (Done)
            Endpoint URL: 
            On the browser:
            ```bash
            http://localhost:18082/sessionsData
            ```

4. Understand the changes necessary to the Mallory Server to enable the Man in the Middle Attack (Done)
        - Client ID on the Alice side can be kept constant and transparent in this attack.
        - Nonces on the Mallory side should be independently created to guarantee security on both ends of the communication.
        - Different sessions IDs can be used in the MIM attack, but the confirmation message should keep the real session from the server.
        - Adapt sessions data structure on the Mallory side to reflect this symmetry.

5. Implement the MITM attack (Done)
        Alice → Mallory → Server → Mallory → Alice

        Alice → Mallory (already done via regular server code)

        Mallory → Server (already done via regular client code)

        Server → Mallory (already done via regular client code)

        Mallory → Alice (Done, forwarded session id, confirmation message of real server, changed server nonce and iv and encrypted
                                confirmation message with private key from connection from Mallory and Alice)

6. Run the static code analysis on the current code and fix problems (Done)
7. Place the Diffie Hellman key exchange's tests from previous challenges working again (Done)
8. Implement the tests of the MITM attack without parameter injection (Done)
9. Implement parameter injection (Done)
10. Add tests to test parameter injection as well (Done)
11. Add the /MessageExchange route to the server endpoint (Done)
12. Add the /MessageExchange route to the client endpoint (Done)
13. Add tests to the /MessageExchange route to the DH protocol on the server side (Done)
14. Refactor existing tests to include also the returned session ID on the client side, on the tuple (Done)
15. Add tests to the normal exchange in the DH protocol for the /messageExchange route (Done)
16. Add the /MessageExchange route to the Mallory server endpoint (Done)
17. Add the tests to the normal MITM attack for the /messageExchange route (Done)
18. Add the tests to the MITM attack with parameter injection for the /MessageExchange route (Done)
19. Run static code analysis and fix problems (Done)

20. Read entire code and fix some bugs that might still be there (in progress)
    - Client.hpp (Done)
    - Client.cpp (Done)

    - DhParametersLoader.hpp (Done)
    - DhParametersLoader.cpp (Done)

    - DiffieHellman.hpp (Done)
    - DiffieHellman.cpp (Done)

    - EncryptionUtility.hpp (Done)
    - EncryptionUtility.cpp (Done)

    - MalloryServer.hpp (Done)
    - MalloryServer.cpp (Done)

    - MallorySessionData.hpp (Done)
    - MallorySessionData.cpp (Done)

    - MessageExtractionFacility.hpp (Done)
    - MessageExtractionFacility.cpp (Done)

    - Server.hpp (Done)
    - Server.cpp (Done)

    - SessionData.hpp (Done)

    - runClient1.cpp (Done)
    - runMalloryServer.cpp (Done)
    - runServer.cpp (Done)

21. Create UML class diagram (Done)
    - Server (Done)
    - DhParametersLoader (Done)
    - DiffieHellman (Done)
    - EncryptionUtility (Done)
    - MalloryServer (Done)
    - MallorySessionData (Done)
    - MessageExtractionFacility (Done)
    - SessionData (Done)

22. Create UML sequence diagram (Done)

    - To generate the sequence diagram in .svg format, run this command at the 'uml_diagrams' folder:
    
    ```bash
    java -jar /home/tiago-sousa/.vscode/extensions/jebbs.plantuml-2.18.1/plantuml.jar -tsvg sequence_diagram.puml
    ```

23. Double check all the content from the UML sequence diagram (Done)
24. Write article about this project (in progress)
        URL link: https://www.linkedin.com/article/edit/7347185167901364224/
        
        24.1. What is and how it works the man in the middle attack in the context of the Diffie Hellman key exchange protocol (Done)
        24.2. What is and how it works the parameter injection in the context of the Diffie Hellman key exchange protocol (Done)
        24.3. What was the structure used in this prove of concept, and the results obtained (Done)
        24.4. A quick demo of the attack taken place (in progress)
        24.5. A mitigation action to prevent this attack and why it works (TBD)
