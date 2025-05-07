[Test Cases for HMAC-MD5 and HMAC-SHA-1](https://datatracker.ietf.org/doc/html/rfc2202)


1. Create empty main folders for this problem (Done)  
2. Copy CMakeLists.txt from the past problem (Done)  
3. Understand the problem and come up with a plan to fix it (Done)  
4. Implement skeleton of the Server (Done)  
5. Implement skeleton of the testServer (Done)  
6. Migrate the SHA-1 from previous problems (Done)  
7. Read the information about HMAC (Done)  
8. Implement the HMAC-SHA1 (Done)  
9. Implement the tests for HMAC-SHA1 (Done)  
10. Implement the test of the edge cases for HMAC-SHA1 (Done)  
11. Install locally Crow dependencies (Done)  
12. Install remotely Crow dependencies (Done)  
13. Install and run locally Crow (Done)  
14. Install and run remotelly Crow (Done)  
15. Read documentation about the Crow framework (Done)  
    [Crow documentation](https://crowcpp.org/master/guides/)  
16. Add a secret key in the server side locally (Done)  
17. Add a secret key in the server side remotely (Done)  

18. Add the configuration for the Crow web server inside the server (Done)  

19. Test manually changing in the browser URL to verify that the server is working properly (Done)  
    19.1. Test URL with valid signature (Done)  
    19.2. Test URL with invalid signature (Done)

20. Add unit tests in the Server side (Done)

21. Add Attacker code to call the server's side with URL requests (Done)

    21.1. Test URL with valid signature, server side should accept request (Done)  
    21.2. Test URL with invalid signature, server side should deny the request (Done)

22. Understand how the attack is done (Done)
23. Implement the insecure compare (Done)
24. Implementation of the attack on the attacker side (Done)
25. Update the attack to be able to handle noise and statistical variation between samples. (Done)

26. Add unit tests that bypass the delay induced by the attack (in progress)
