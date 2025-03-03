# Description of Work (10 points)

For this project, I did not really make any big design choices other than just following the spec. I decided to track the handshake stage using a variable
so that I could verify that messages were sent at the correct times and so that I could process the message correctly at each step. The code was separated
for server and client for only the handshake portions, otherwise, the two shared the encrypting and decrypting code. 

The main problems I had were keeping track of the stages I was on during the handshake for both the server and the client. For example, I had an issue where
my program would unintentionally try to extract a IV and CIPHERTEXT TLV from the FINISHED message and hang because of that. This was because of how I had
set the SERVER state to ready to exchange data after processing the FINISHED message, but it would immediately treat the FINISHED message as a new input. 
To fix this, I just added some early returns so that the function would stop after processing the FINISHED message. Another problem I had was with creating
the data buffers for things like the hmac digest or the salt for HKDF (basically scenarios where I had to append things together). I was initially reusing the 
buffer parameter to do all this; however, this caused issues with overwriting things, so I just started creating new buffers for every instance. Honestly, the
biggest hurdle I had was trying to understand the spec and all the provided functions. There were times where I did not really understand what I had to do or
how to do it. 
