Make sure you are disabling relocation in a PE Editor after compiling the test samples.
For exmaple, open "CFF Explorer", go to "PE_OptionalHeader"/"DllCharacteristics" and disable "DLL can move"

Otherwise you need to change the things like the start/end range of your client all the time, or 
fix certain function offsets you are trying to patch.

