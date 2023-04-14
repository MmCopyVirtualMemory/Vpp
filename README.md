# Voyager++
Utility modifications to Voyager. 

*If I am not lazy I will post pictures from windbg of how I found all of this and various additions that I have made to the payload itself but this is for another time.*

# Operations Without VDM's Shithook
There has been a very poorly written library being passed around (and sold) like an albanian prostitute which utilizes vdm. I intend to demonstrate how to use voyager (and any other library like it) without the use of the shithook.

Firstly read the PsInitialSystemProcess from ntoskrnl by using the kernel dirbase for translation. In theory you could also use the dirbase of the current process (since the kernel is mapped into every process) but in some cases this might not be available whereas the kernel dirbase doesn't change (from what I saw in windbg).
```cpp
ReadVirt(kernel_dirbase, ntoskrnl_base + OFFSET_INITIALSYSTEMPROCESS, &kernel_peprocess, sizeof(kernel_peprocess));
```
PsInitialSystemProcess iteration so no need for a calling things like PsLookupProcessByProcessId.
```cpp
static bool LoopPeProcesses(std::function<void(int, GUEST_VIRT)> callback)
{
	GUEST_VIRT apl_head = kernel_peprocess + OFFSET_APL;
	GUEST_VIRT current_ptr = apl_head;
	LIST_ENTRY current = {};
	ReadVirt(kernel_dirbase, current_ptr, &current, sizeof(current));
	while (current.Flink != (void*)apl_head)
	{
		GUEST_VIRT peprocess = current_ptr - OFFSET_APL;
		U64 pid = {};
		ReadVirt(kernel_dirbase, peprocess + OFFSET_PID, &pid, sizeof(pid));
		callback(pid, peprocess);
		current_ptr = (GUEST_VIRT)current.Flink;
		ReadVirt(kernel_dirbase, current_ptr, &current, sizeof(current));
	}
	return true;
}
```
Now that we have the PEPROCESS, we can freely use it to gather data about the process from reads instead of using calls.

This is an example of how I previously used the code. It is very old and can be written in a more efficient way:
```cpp
static GUEST_VIRT GetProcessBaseAddress(int pid)
{
	GUEST_VIRT base = {};
	bool success = LoopPeProcesses(
		[&](int current_pid, GUEST_VIRT peprocess)
		{
			if (pid == current_pid)
			{
				ReadVirt(kernel_dirbase, peprocess + OFFSET_BASE, &base, sizeof(base));
			}
		}
	);
	return base;
}
static GUEST_VIRT GetPeb(int pid)
{
	GUEST_VIRT ppeb = {};
	bool success = LoopPeProcesses(
		[&](int current_pid, GUEST_VIRT peprocess)
		{
			if (pid == current_pid)
			{
				ReadVirt(kernel_dirbase, peprocess + OFFSET_PEB, &ppeb, sizeof(ppeb));
			}
		}
	);
	return ppeb;
}
static GUEST_PHYS GetDirbase(int pid)
{
	static std::map<int, GUEST_PHYS> dirbase_map = {}; //this will save time doing lookups but might cause problems.
	if (dirbase_map[pid])
	{
		return dirbase_map[pid];
	}
	else
	{
		bool success = LoopPeProcesses(
			[&](int current_pid, GUEST_VIRT peprocess)
			{
				if (!dirbase_map[current_pid])
				{
					GUEST_PHYS current_dirbase = {};
					ReadVirt(kernel_dirbase, peprocess + OFFSET_DIRBASE, &current_dirbase, sizeof(current_dirbase));
					dirbase_map[current_pid] = current_dirbase;
				}
			}
		);
	}
	return dirbase_map[pid];
}
```
