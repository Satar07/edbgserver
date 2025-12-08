- fix: Any thread that wasn’t explicitly resumed by a set_resume_action_XXX
  method should be resumed as though it was resumed with set_resume_action_continue.
- fix: svc next pc (uprobe cant attach there)
- feat: HostIo trait for reading/writing to host memory
- feat: ExecFile trait for executing files in the target
