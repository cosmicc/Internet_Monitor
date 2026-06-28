# Installation

1. Create a new Portainer stack from the Git repository.
2. Use `docker-compose.yml` as the compose path.
3. Set environment overrides in Portainer if the defaults in `.env.example` are
   not appropriate.
4. Deploy the stack.

The stack builds the image from this repository, grants only `NET_RAW` for
fping, publishes the web UI on port `5005` by default, and stores runtime data in
the `internet-monitor-data` Docker volume.

## Useful Commands

```bash
docker compose logs -f
docker compose ps
docker compose down
```

To reset logs and status, remove the `internet-monitor-data` volume after the
stack is stopped.
