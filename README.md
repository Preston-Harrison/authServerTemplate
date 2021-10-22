# authServerTemplate
A template for server-side JWT authentication 
server.js contains how this could be implemented in an express JS server. routes/token.js contains the code that manages the JWT authentication.

When you use this, probably use local environment variables as a private key. Also for gods sake please add your private key files to .gitignore, you don't want to accidentally publish them. To do this, read dotenv documentation.
