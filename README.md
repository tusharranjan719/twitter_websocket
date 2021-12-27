# twitter_websocket
We have implemented websocket interface along with public key based authentication for the Project 4 part 2. The user functionalities provides are same as previous project, which includes login, sign up, tweet, retweet, follow, logout, view tweets, hashtags etc. 
Tushar Ranjan - 45562694
Sankalp Pandey – 92878142

Video Link
https://youtu.be/7KkW-PgsLUs

How to run
1.	Server:
Run the file ‘Server.fs’ using command:
a.	dotnet run – run twitter server
b.	dotnet run tester – to see authentication messages
2.	Client:
Run the file ‘Client.fs’ using commands: 
a.	dotnet run user – run the code to use twitter
b.	dotnet run tester – additional features to see authentication messages and JSONs shared by client and server

Brief Description
We have implemented websocket interface along with public key based authentication for the Project 4 part 2. The user functionalities provides are same as previous project, which includes login, sign up, tweet, retweet, follow, logout, view tweets, hashtags etc. 

What is working 
All twitter functionalities from previous requirement.
P JSON based API to communicate between client and server
P WebSharper interface for client and server

BONUS:
P User’s 256 bit EclipticCurve public key after registration using Diffie-Helman protocol
P Challenge based algorithm:
	P 256-bit challenge
	P Client signs challenge + unix time 
	P Servers confirmation/error
	P 1 second cache for challenge
P Using HMAC to sign the messages.


![image](https://user-images.githubusercontent.com/68017211/147442893-8db3a6c0-1d5b-4cef-9cc8-c8ccd1ed6883.png)
