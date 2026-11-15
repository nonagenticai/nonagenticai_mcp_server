# start_fr_project

External tool (runtime `fr_project`, no Kata package). Starts an fr project in the calling
tenant's fr workspace as the agent member. Task lifecycle: `input_required` while fr waits for
the start confirmation or a conveyor answer, `completed` when fr marks the project delivered.
