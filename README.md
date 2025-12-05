# secure-auth-project
Build Secure PKI-Based 2FA Microservice with Docker


## Running the Docker Image

### Default Run (Port 8080)
The application inside the container always runs on port 8080.

`docker run -p 8080:8080 ravireddy2005/secure_auth_project`

Access it at:

`http://localhost:8080`

## If Port 8080 Is Already In Use
### Change the Host Port in the docker run Command

If your system already uses 8080 for another application, you can map the container port 8080 to any free host port.

Examples:

`docker run -p 9000:8080 ravireddy2005/secure_auth_project`

`docker run -p 5000:8080 ravireddy2005/secure_auth_project`

Now open:

`http://localhost:9000`
(Or whichever host port you selected.)

## Example Using Docker Compose

Change the port section in `docker-compose.yml` file 

`ports:`

  `- "9000:8080"   # change 9000 to any free port, if your 8080 port not available. `

Run:

`docker compose up -d`

THANK YOU!
