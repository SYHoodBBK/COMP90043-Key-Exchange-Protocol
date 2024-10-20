# Key Exchange Protocol based on X3DH and Double Ratchet
### Project description

This project provides two Docker image files for x86 and arm64 platforms.

### Importing Docker images

Depending on the platform you are using, select the appropriate command below to import the image files:

- For x86 platforms:

```bash
docker load < signal-app_x86.tar
```

- For arm64 platforms:

```bash
docker load < signal-app_arm64.tar
```

### Running the Docker container

Use the following commands to run the Docker container on both ports at the same time:

```bash
docker run -p 5000:5000 -p 23456:23456 signal-app
```

### Access to the chat program

Access the online chat program by visiting http://localhost:5000 in your browser.

### Instructions for use

1. Click on "Bob's Chat" to go to Bob's page for the first time.

2. On Bob's page, you will be prompted to wait for Alice to connect. In this case, please create a new tab in your browser, visit the web page again, and click "Alice's Chat" to enter Alice's page.

3. After Alice sends the first message, Bob can start to reply. At this point, both parties can send messages to each other.

4. When Ratchet Advancements are made, the system will display a message indicating the ratchet change.

### Note

As this project focuses on the implementation of encryption protocols, the web interface is basic and only allows the first user to enter the web page to access the chat system as Bob. If you need to reset the chat or test again, try restarting the Docker container and opening the web page in a new tab to access it.