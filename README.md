# MinHook

The Minimalistic x86/x64 API Hooking Library for Windows

http://www.codeproject.com/KB/winsdk/LibMinHook.aspx

### Version history

- ####v1.3 - 

  * Fixed some small bugs.
  * Reorganized the source files.

- ####v1.3-beta - 17 Jul 2014

  * Rewrote in plain C to reduce the footprint and memory usage. (suggested by Andrey Unis)
  * Simplified the overall code base to make it more readable and maintainable.
  * Changed the license from 3-clause to 2-clause BSD License.

- ####v1.2 - 28 Sep 2013
 
  * Removed boost dependency ([jarredholman](https://github.com/jarredholman/minhook)).
  * Fixed a small bug in the GetRelativeBranchDestination function ([pillbug99](http://www.codeproject.com/Messages/4058892/Small-Bug-Found.aspx)).
  * Added the ```MH_RemoveHook``` function, which removes a hook created with the ```MH_CreateHook``` function.
  * Added the following functions to enable or disable multiple hooks in one go: ```MH_QueueEnableHook```, ```MH_QueueDisableHook```, ```MH_ApplyQueued```. This is the preferred way of handling multiple hooks as every call to `MH_EnableHook` or `MH_DisableHook` suspends and resumes all threads.
  * Made the functions ```MH_EnableHook``` and ```MH_DisableHook``` enable/disable all created hooks when the ```MH_ALL_HOOKS``` parameter is passed. This, too, is an efficient way of handling multiple hooks.
  * If the target function is too small to be patched with a jump, MinHook tries to place the jump above the function. If that fails as well, the ```MH_CreateHook``` function returns ```MH_ERROR_UNSUPPORTED_FUNCTION```. This fixes an issue of hooking the LoadLibraryExW function on Windows 7 x64 ([reported by Obble](http://www.codeproject.com/Messages/4578613/Re-Bug-LoadLibraryExW-hook-fails-on-windows-2008-r.aspx)).

- ####v1.1 - 26 Nov 2009

  * Changed the interface to create a hook and a trampoline function in one go to prevent the detour function from being called before the trampoline function is created. ([reported by xliqz](http://www.codeproject.com/Messages/3280374/Unsafe.aspx))
  * Shortened the function names from ```MinHook_*``` to ```MH_*``` to make them handier.

- ####v1.0 - 22 Nov 2009
 
  * Initial release.
