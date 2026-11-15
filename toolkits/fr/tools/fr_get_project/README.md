# fr_get_project

External tool (runtime `fr_command`, no Kata package). Reads one fr project in the calling
tenant's fr workspace as the agent member, through fr's signed `mcp` channel command
`projects.get {"id":"<uuid>"}`. Pure read, idempotent, no project is created or changed.
