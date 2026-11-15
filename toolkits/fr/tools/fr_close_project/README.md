# fr_close_project

External tool (runtime `fr_command`, no Kata package). Closes one fr project in the calling
tenant's fr workspace as the agent member, through fr's signed `mcp` channel command
`projects.close {"id":"<uuid>"}`. The answer carries the closed project (status, phase, delivery
evidence, deliverables), `closed` / `already_closed` (closing twice is not an error) and
`rm_pm_project_id`. Side effect: closes the project in fr.
