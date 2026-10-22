# Deployment

- Public URL: https://llmwebmail.fs-playground.com/
- Host: `azureuser@llmbank.fs-playground.com`
- Remote app: `/home/azureuser/llm-webmail`
- Local branch: `authentication`. Deploy committed source with `./scripts/deploy.sh`.
- The deployer sends a source archive over SSH; server-side Git access is not required.
- The remote Git checkout contains historical custom changes. Never reset or clean it. Deployment records the source commit in `.deployed-revision`.
- The existing virtualenv is reused. The deployer stops if requirements differ; dependency changes require their own reviewed installation.

## Persistent state and authentication

Never replace or delete `config.toml`, `.env`, `venv/`, `data.db`, `data.db-wal`, `data.db-shm`, `.session_secret`, or `token_stats.json` during deployment. The deployer stops webmail, backs up source and state under `/home/azureuser/llmwebmail-backups/`, then copies source files without deleting unmatched files.

- The admin username/password and model/provider definitions stay in the remote `config.toml`. Do not print secrets or change the admin password unless explicitly requested.
- Participant configs contain only training controls. Never copy the entire server config or provider parameters into participant records or responses.
- Startup removes server secrets from legacy participant config records without deleting accounts, signup codes or quotas.
- `.session_secret` is a private, generated signing key (mode 0600), preserved across deployments. The old `server.session_secret` setting is no longer used to sign cookies. Never include this private file in source archives or API responses.

## tmux and health checks

- Webmail runs as `python app.py` in **session `0`, window `0`, pane `0`, pane ID `%1`**. This was verified on 22 October 2026.
- Restart only webmail using:
  `ssh -F /home/kyuz0/.ssh/config azureuser@llmbank.fs-playground.com '/home/azureuser/llm-webmail/scripts/start.sh /home/azureuser/llm-webmail %1'`
- The scripts verify that `%1` belongs to the webmail directory, interrupt only its Python process, and reuse its shell. Never kill the pane, window, tmux server or session.
- **Never query, attach to, restart, kill, or otherwise touch session `myllmbank`; it belongs to MyLLMBank.** MyLLMBank's public URL is https://llmbank.fs-playground.com/.
- Verify webmail with `curl -fsS -o /dev/null http://127.0.0.1:5001/` on the host. The public URL should also respond successfully.
- Logs: `/home/azureuser/llm-webmail/webmail.log`. Startup can take several minutes; investigate a progressing startup before declaring failure.
- Run `venv/bin/python -m unittest -v test_config_security` for the isolated authentication/config regression suite. It makes no model calls and uses temporary databases.
