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

4. Understand the changes necessary to the Mallory Server to enable the Man in the Middle Attack (in progress)
        - Client ID on the Alice side can be kept constant and transparent in this attack.
        - Nonces on the Mallory side should be independently created to guarantee security on both ends of the communication.
        - Different sessions IDs can be used in the MIM attack, but the confirmation message should keep the real session from the server.
        - Adapt sessions data structure on the Mallory side to reflect this symmetry.

        Alice ---> Mallory ----> Server -----> Mallory ------> Alice

        Alice ---> Mallory (already done via regular server code)

