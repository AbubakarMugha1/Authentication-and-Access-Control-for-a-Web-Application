We implemented the OUTH2 framework using a dummy authorization server. 
The key idea is to understand the information flow in OAUTH2 and how the protected user resources are lent to the requesting client application. The project involves the retrieval of 
an access token (JWT) from the authorization server, decoding the token to extract important information and safely store the session information. Furthermore, I've created my own session tokens
to simplify the process of session validation. This is all present in the app.py

The access control configuration file simply shows the endpoint availability to each type of application user. The functionality itself is very simple and is a very good starting point
if you are looking to understand network security frameworks.
