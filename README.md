# MinHook

A windows api hooking library originally written by Tsuda Kageyu.

http://www.codeproject.com/KB/winsdk/LibMinHook.aspx

## Main differences from original v1.1

* Removed boost dependency ([jarredholman](https://github.com/jarredholman/minhook)).
* Fixed a small bug in the GetRelativeBranchDestination function ([pillbug99](http://www.codeproject.com/Messages/4058892/Small-Bug-Found.aspx)).
* Added the `MH_RemoveHook` function, which removes a hook created with the `MH_CreateHook` function.
* Added the following functions to enable or disable multiple hooks in one go: `MH_EnableAllHooks`, `MH_DisableAllHooks`, `MH_EnableMultipleHooks`, `MH_DisableMultipleHooks`. This is the preferred way of handling multiple hooks as every call to `MH_EnableHook` or `MH_DisableHook` suspends and resumes all threads.
