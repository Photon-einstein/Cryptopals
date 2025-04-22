1. Get to know better what is MD4 (Done)

    ## References
    - [RFC 1320: The MD4 Message-Digest Algorithm (1990)](https://www.rfc-editor.org/rfc/rfc1320.html) by Ronald L. Rivest (MIT)

2. Implement the MD4 algorithm following the paper description (in progress)  
    
    2.1. Add Message Digest skeleton header and cpp files (Done)  
    2.2. Add MD4 skeleton header and cpp files (Done)
    2.3. Add MD4 initialization method (Done)
    2.4. Add MD4 padding (Done)
    2.5. Add MD4 helper methods f(), g() and h() (Done)
    2.6. Add round 2 and 3 constants to MD4 (Done)
    2.7. Add the processing method into MD4 (in progress)
        2.7.1 Add round 1 operations (Done)
        2.7.2 Add round 2 operations (Done)
        2.7.3 Add round 3 operations (Done)
    2.8. Add final output of the hash value (Done)

3. Add unit tests to MD4 and verify its proper functioning (Done)

4. Implementation of the Length Extension Attack (TBD)
    4.1. Implementation of the custom initialization method at MD4 (Done)
    4.2. Implementation of the custom hash method at MD4 (Done)
    4.3. Implementation of the auxiliary method of the attacker, namely extractMessage (Done)
    4.4. Implementation of the auxiliary method of the attacker, namely parseMessage (Done)
    4.5. Implementation of the auxiliary method of the attacker, namely computeMD4Padding (Done)
    4.6. Implementation of the auxiliary method of the attacker, namely extractionMD4InternalState (Done)
    4.6. Implementation of the auxiliary method of the attacker, namely tamperMessageTry (Done)
    4.7. Implementation of the method validateMac of the attacker (Done)
 
    4.8. Add unit tests to the attacker (Done)
    4.9. Add unit tests to the server (Done)

5. Fix quality errors detected with the static code analysis (Done)

6. Complete UML class and sequence diagrams (Done)
    6.1. Complete UML class diagram (Done)
    6.2. Complete UML sequence diagram (Done)

7. Write an article (in progress)
    7.1. Explain what MD4 (Done)
    7.2. Explain the mechanism of MD4 (Done)
    7.3. Explain why is it vulnerable (Done)
    7.4. Explain the differences between MD4, SHA1 and the other algorithms based on the Merkle-Damgard construction (Done)
    7.5. Explain the length extension attack for MD4 (Done)
    7.6. Include reference of the paper that suggested the creation of MD4 in a RFC reference (Done)




