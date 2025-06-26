1. Explore what is the man in the middle attack (Done)
2. Explore what would need to change to the original setup of the protocol (Done)
    Port of Mallory 18080 (production)
    Port of Mallory 18081 (test)

    Port of Server  18082 (production)
    Port of Server  18083 (test)

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

20. Read entire code and fixe or enhance some bugs that might still be there (in progress)

21. Create uml class diagram (TBD)
22. Create uml sequence diagram (TBD)
23. Write article about this project (TBD)
