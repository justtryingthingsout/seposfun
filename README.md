# MADE BY PLX, EXPLOIT3D (MD) HAS NOTHING TO DO WITH THAT CRINGE... 

# seposfun
Incomplete project for SEP bypass for downgrades/dual-boots. We decided to abandon this project and release it as it is since we have blackbird SEPROM Exploit which is much more powerful. This should allow you to boot up device without SEPOS however iOS Support is incomplete. This was tested on several NonUI builds and it seems it will only work on it. There is a possibility that older iOS versions will boot fine, feel free to make pull requests. 
# Tools
iPatcher - Tool to patch iBoot for older iOS versions

sepless - tool to disable SEPOS and AppleKeyStore from kernel. (10.3->11.4.1 were tested)

keybagd_bypass - very easy code just to replace keybagd
# How to use

NOTE: decryptions keys can be found on iphonewiki

1. decrypt and patch iBSS/iBoot/iBEC

`img4 -i iBSS/iBoot/iBEC.RELEASE.XX.im4p -o iBSS/iBoot/iBEC.RELEASE.XX.dec -k ivkey`

In case of iOS 10 and later you can use iBoot64Patcher by @tihmstar or kairos by @dayt0nhasty. 

`kairos ibss.dec ibss.pwn`

`kairos iBEC/iBoot.dec iBEC/iBoot.pwn -b "-v rd=disk0s1sX"`

or

`iBoot64Patcher ibss.dec ibss.pwn`

`iBoot64Patcher iBEC/iBoot.dec iBEC/iBoot.pwn -b "-v rd=disk0s1sX"`

In case of iOS 9 and older we need to use iPatcher. Note: I still haven't updated boot-args patch to allow longer boot-args so you will have to inject them yourself if they are too long.

`iPatcher ibss.dec ibss.pwn`

`iPatcher iBEC/iBoot.dec iBEC/iBoot.pwn -b "-v rd=disk0s1sX"`

Now we need to pack our images. For this purpose we will use img4tool by @tihmstar

`img4tool -c iBSS.im4p --type ibss --desc ibss ibss.pwn`

`img4tool -p iBSS.im4p -c iBSS.img4 -s shsh.shsh2`

`img4tool -c iBEC/iBoot.im4p --type ibec --desc ibec iBEC/iBoot.pwn`

`img4tool -p iBEC/iBoot.im4p -c iBoot.img4 -s shsh.shsh2`

2. Patching kernel 

Firstly let's decrypt/unpack the kernel

`img4 -i kernelcache.release.XX.im4p -o kcache.raw`

iOS 9 and below has kernel encrypted meaning you also have to input IV and KEY

`img4 -i kernelcache.release.XX.im4p -o kcache.raw -k ivkey`

Now we need to patch AMFI and SEPOS/AppleKeyStore stuff in kernel, we'll use Kernel64Patcher by @Ralph0045

`Kernel64Patcher kcache.raw kcache.pwn -a`

`sepless kcache.pwn kcache.pwn2 (-d)` (-d option is in case of DEVELOPMENT kernelcaches)

Next step is to generate diff between patched kernel and stock kernel. Fortunately @mcg29_ wrote tool for us

`python3 compareFiles.py kcache.raw kcache.pwn2`

Now we will apply patch to actual IM4P kernelcache. In case of iOS 9 and below make sure to re-decrypt kernelcache but with -D flag since we want have decrypted compressed kernelcache 

`img4 -i kernelcache.release.XX.im4p -o kernelcache.release.XX_decrypted.im4p -k ivkey -D`

then

`img4 -i kernelcache.release.XX.im4p/kernelcache.release.XX_decrypted.im4p -o kernelache_patched.im4p -P kc.bpatch`

`img4tool -c kernelcache_patched.img4 -p kernelache_patched.im4p -s shsh.shsh2`

Now open `kernelcache_patched.img4` in hex editor and change `krnl` to `rkrn`

You're done. Make sure to make IMG4 from IM4P devicetree with tag `rdtr`

Don't forget to replace /usr/libexec/keybagd with keybagd_bypass

# Thanks to
xerub - patchfinder64
