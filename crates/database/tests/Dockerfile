FROM rust:1.97
WORKDIR /workspace
COPY . .
CMD ["cargo", "test", "-p", "piquel-repository", "--test", "identity", "--", "--ignored", "--test-threads=1", "--nocapture"]
