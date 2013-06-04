# MinHook

A Windows API hooking library originally written by Tsuda Kageyu.

http://www.codeproject.com/KB/winsdk/LibMinHook.aspx

## Main differences from original v1.1

* Removed boost dependency ([jarredholman](https://github.com/jarredholman/minhook)).
* Fixed a small bug in the GetRelativeBranchDestination function ([pillbug99](http://www.codeproject.com/Messages/4058892/Small-Bug-Found.aspx)).
* Added the `MH_RemoveHook` function, which removes a hook created with the `MH_CreateHook` function.
* Added the following functions to enable or disable multiple hooks in one go: `MH_EnableAllHooks`, `MH_DisableAllHooks`, `MH_EnableMultipleHooks`, `MH_DisableMultipleHooks`. This is the preferred way of handling multiple hooks as every call to `MH_EnableHook` or `MH_DisableHook` suspends and resumes all threads.
* Made the `MH_CreateHook` function return `MH_ERROR_UNSUPPORTED_FUNCTION` when the target function is too small and is not padded with zero bytes, nops, or INT3 commands.
* If the target function begins with a short jump, MinHook considers the jump destination as the target ([Obble](http://www.codeproject.com/Messages/4578613/Re-Bug-LoadLibraryExW-hook-fails-on-windows-2008-r.aspx)). This fixes an issue on Windows 7 x64 with the patched jump overwriting code of a different function.
