# KGPU - Augmenting Linux with GPUs

## Important note:

- The master branch is tested on Linux 3.10. If you want to try KGPU on recent kernels, additional changes and compatibility tests are needed.

- I don't have time to modify everything to comply with the latest kernel, so master branch has ecryptfs and raid6 services disabled. Just leaves an example service for hubbyists to borrow code to start with their own service development.


## What is it?

- Treating the GPU as a computing co-processor. To enable the data-parallel computation inside the Linux kernel. Using SIMD (or SIMT in CUDA) style code to accelerate Linux kernel  functionality.
  
- Make the Linux kernel really parallelized: which is not only processing multiple requests concurrently, but can also partition
     a single large requested computation into tiles and do them on GPU cores.
     
- GPU can give the OS kernel dedicated cores that can be fully occupied by the kernel. But the multicore CPUs should not be
     occupied by the kernel because other tasks also need them.
     
- KGPU is not an OS running on GPU, which is almost impossible because of the limited functionality of current GPU
     architectures. KGPU tries to enable vector computing for the kernel.

As for copyright license, we use GPLv2.

## News
- RAID6 PQ computing function added as a service, gpq module for its kernel part to replace the global raid6_call algorithm with GPU one, it can beat the fastest SSE version  with 16 disks and >= 1MB data on my machine. Try it with a RAID6 on dm driver.
- Scripts to run and stop kgpu.
- Simple build system.
- dm-security can use gecb, gctr or gxts directly.

## Try it?

### Hardware:
We use Tesla T4. You don't need such high-end video card, but you should have a NVIDIA card that support CUDA computing capability 2.0 or higher. 

If you don't have more than 1G video memory, change KGPU_BUF_SIZE in kgpu/kgpu.h to make sure KGPU_BUF_SIZE*2 < Size of Your Video Memory - (x) where the max of x is a value that you need try some times to figure out. Or simply leave x = 64M or 128M.

Notice a new change: we enabled a new feature to allow KGPU remapping any kernel pages into CUDA page-locked memory, the remapping also need video memory on the GPU side, so now there are two GPU buffers with the same size, which is KGPU_BUF_SIZE. So KGPU_BUF_SIZE should be <= video memory size/2.

### Software:
We compile the CUDA code with nvcc in CUDA 11.7. The OS kernel is Linux 3.10. You MUST use a 64bit linux kernel compiled targeting at x86_64!

Make and Run it:
1. Check out the code from Github or download the archive from Google Code and extract files into say kgpu directory:

    ```cd kgpu && make all```

2. Now all outputs are in build directory. To run it:

  ```cd build && sudo ./runkgpu```

3. This only starts KGPU module, helper and loads AES ciphers. To use modified dm-crypt, in the build directory:

    ```sudo insmod ./dm-crypt.ko```

    NOTE: DO NOT USE THIS ECRYPTS FOR IMPORTANT DATA!!!
    THIS IS NOT COMPATIBLE WITH THE VANILLA ECRYPTFS.
    SAME CARE SHOULD BE TAKEN WITH DM-CRYPT.

4. To stop it:

    Umount your dm-crypt partition, delete dm-crypt mappers and:

    ```sudo rmmod dm-crypt```

    Stop "helper" program by Ctrl-C

    ```sudo ./stopkgpu (in build/)```

Weibin Sun, Xing Lin, Peihong Chen
{wbsun, xinglin}@cs.utah.edu, mf21320017@smail.nju.edu.cn
