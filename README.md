# nissinfect

This project allows to `merge` two portable executables by copying the sections from the Source PE into the Target PE and adding an extra Stub section that will be the new Entry Point. The Stub code calls into the original entry points of both the Source and the Target PEs.

No relocations or data directory information is modified. If these are needed by the source PE then it probably won't work with the current implementation.

This was done to combine the functionality of UEFI images into a single module. This seem to work because these images do not use all the chracteristics from the PE format. This allows to backdoor an SMM or DXE module with another malicious module and keep the functionality of the original.