// sepless is part of seposfun (c) tools
// made by @exploit3dguy 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../patchfinder64/patchfinder64.c"

#define GET_OFFSET(klen, x) (x - (uintptr_t) kbuf) // Thanks to @Ralph0045 for this 

addr_t xref_stuff;
void *str_stuff;
addr_t beg_func;

bool dev_kernel = false;
int version;
void* xnu;

int findandpatch(void* kbuf, size_t klen, void* string, void* searchstr) {
    //printf("klen: %zu\nkbuf: %p\ncurrent str: %s\nsearch term: %s\n", klen, kbuf, (char *)string, (char *)searchstr);
    str_stuff = memmem(kbuf, klen, searchstr, strlen(searchstr) - 1);
    if (!str_stuff) {
        printf("[-] Failed to find %s string\n", string);
        return -1;
    }
    
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    beg_func = bof64(kbuf,0,xref_stuff);

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched %s\n", string);
    return 0;
}

int get_sep_patch(void* kbuf, size_t klen) {
    void* strings[] = {
        "AppleSEPFirmware initFromMemory",
        "AppleSEPManager setFirmwareBytes",
        "AppleSEPBooter bootAction",
        "AppleSEPBooter bootSEP"
    };
    void* search[] = {
        "void AppleSEPFirmware::_initFromMemory",
        "IOexit(AppleSEPManager::setFirmwareBytes",
        "void AppleSEPBooter::_bootAction",
        "IOexit(AppleSEPBooter::bootSEP",
    };
    void* searchalt[] = {
        "bool AppleSEPFirmware::_initFromMemory",
        "IOReturn AppleSEPManager::setFirmwareBytes",
        "IOReturn AppleSEPBooter::bootSEP"
    };
    if (dev_kernel == true) {
    	xnu = memmem(kbuf,klen,"root:xnu_",9);
        version = atoi(xnu+20);
    } else {
        xnu = memmem(kbuf,klen,"root:xnu-",9);
        version = atoi(xnu+9);
    }
    if (version <= 4570) {
        printf("getting %s()\n", __FUNCTION__);
        if (findandpatch(kbuf, klen, strings[0], search[0]) != 0) {
            printf("Trying again with another search term\n");
            findandpatch(kbuf, klen, strings[0], searchalt[0]);
        }
        if (findandpatch(kbuf, klen, strings[1], search[1]) != 0) {
            printf("Trying again with another search term\n");
            findandpatch(kbuf, klen, strings[1], searchalt[1]);
        }
        findandpatch(kbuf, klen, strings[2], search[2]);
        if (findandpatch(kbuf, klen, strings[3], search[3]) != 0) {
            printf("Trying again with another search term\n");
            findandpatch(kbuf, klen, strings[3], searchalt[2]);
        }
        printf("%s: quitting...\n", __FUNCTION__);
    }
    return 0;
}

int get_applekeystore_patch(void *kbuf, size_t klen) {
	if (dev_kernel == true) {
    	xnu = memmem(kbuf,klen,"root:xnu_",9);
        version = atoi(xnu+20);
    } else {
        xnu = memmem(kbuf,klen,"root:xnu-",9);
        version = atoi(xnu+9);
    }
    void* search[] = {
        "AppleSEPKeyStore::%s: Failed to prepare output memory descriptor.",
        "AppleKeyStore starting",
        "AppleSEPKeyStore::%s: Failed to initialize _workLoop",
        "AppleSEPKeyStore::%s: _sep_enabled",
        "AppleSEPKeyStore::%s: -- Volume keybags:",
        "AppleSEPKeyStore::%s: Mapping volume without",
        "AppleSEPKeyStore::%s: notified volume uuid %s - locked",
        "AppleSEPKeyStore::%s: notified volume uuid %s - lock state",
        "AppleSEPKeyStore::%s:  %s : %4d (%08x)",
        "AppleSEPKeyStore::%s: ----------------",
        "AppleSEPKeyStore::%s: vfs notification failed",
        "AppleKeyStore: Sending lock change %d",
        "AppleKeyStore: stash expired",
        "AppleSEPKeyStore::%s: keybagd has not registered",
        "AppleSEPKeyStore::%s: failed to notify system keybag updation",
        "AppleSEPKeyStore::%s: failed to notify %d\xA0\x00tickle_backup_notify_port",
        "AppleSEPKeyStore::%s: Volume cookie mismatch",
        "AppleSEPKeyStore::%s: unmapped uuid",
        "AppleSEPKeyStore::%s: mapped uuid",
        "AppleSEPKeyStore::%s: ::sep_endpoint() can't find AppleSEPManager",
        "AppleSEPKeyStore::%s: Can't find AppleSEPManager"
    };
    void* strings[] = {
        "AppleSEPKeyStore failed to prepare output memory descriptor",
        "AppleKeyStore starting",
        "AppleSEPKeyStore failed init _workLoop",
        "AppleSEPKeyStore _sep_enabled",
        "AppleSEPKeyStore volume keybags",
        "AppleSEPKeyStore mapping volume without a cookie",
        "AppleSEPKeyStore notified volume uuid locked",
        "AppleSEPKeyStore notified volume uuid lock state",
        "AppleSEPKeyStore 4d",
        "AppleSEPKeyStore -",
        "AppleSEPKeyStore vfs notif failed",
        "AppleKeyStore sending lock change",
        "AppleKeyStore stash expired",
        "AppleSEPKeyStore keybagd not registered",
        "AppleSEPKeyStore failed to notify system keybag updation",
        "AppleSEPKeyStore failed to notify tickle_backup_notify_por",
        "AppleSEPKeyStore volume cookie mismatch",
        "AppleSEPKeyStore unmapped uuid",
        "AppleSEPKeyStore mapped uuid",
        "AppleSEPKeyStore can't find AppleSEPManager"
    };
    void* strings8[] = {
        "AppleKeyStore starting",
        "Failed to initialize _workLoop",
        "AppleKeyStore:Sending lock change %d",
        "AppleKeyStore:Sending category unlock status with %d",
        "failed to notify %d",
        "failed to notify system keybag updation %d",
        "AppleSEPKeyStore::sep_endpoint() can't find AppleSEPManager",
        "AppleSEPKeyStore::sep_endpoint() failed to initialize",
        "", //seperates search terms and strings
        "Failed to init _workLoop",
        "AppleKeyStore sending category unlock status",
        "Failed to notify",
        "Failed to notify system kbag update",
        "AppleSEPKeyStore sep_endpoint() can't find AppleSEPManager",
        "AppleSEPKeyStore sep_endpoint() failed to init"
    };
    if (version <= 4570) {
        printf("getting %s()\n", __FUNCTION__);
        if ((2783 >= version) && (version <= 2784)) {
            printf("iOS 8 detected\n");
            findandpatch(kbuf, klen, strings[1], strings8[0]);
            findandpatch(kbuf, klen, strings8[9], strings8[1]);
            findandpatch(kbuf, klen, strings[11], strings8[2]);
            findandpatch(kbuf, klen, strings8[10], strings8[3]);
            findandpatch(kbuf, klen, strings8[11], strings8[4]);
            findandpatch(kbuf, klen, strings8[12], strings8[5]);
            findandpatch(kbuf, klen, strings8[13], strings8[6]);
            findandpatch(kbuf, klen, strings8[14], strings8[7]);
            printf("%s: quitting...\n", __FUNCTION__);
            return 0;
        }
        findandpatch(kbuf, klen, strings[0], search[0]);
        findandpatch(kbuf, klen, strings[1], search[1]);
        findandpatch(kbuf, klen, strings[2], search[2]);
        if (version <= 3789) {
            printf("[*] Skipping patch: %s\n", strings[3]);
            printf("[*] Skipping patch: %s\n", strings[4]);
            printf("[*] Skipping patch: %s\n", strings[5]);
            printf("[*] Skipping patch: %s\n", strings[6]);
            printf("[*] Skipping patch: %s\n", strings[7]);
        } else {
            // 11.x stuff
            findandpatch(kbuf, klen, strings[3], search[3]);
            findandpatch(kbuf, klen, strings[4], search[4]);
            findandpatch(kbuf, klen, strings[5], search[5]);
            findandpatch(kbuf, klen, strings[6], search[6]);
            findandpatch(kbuf, klen, strings[7], search[7]);
        }
        findandpatch(kbuf, klen, strings[8], search[8]);
        findandpatch(kbuf, klen, strings[9], search[9]);
        findandpatch(kbuf, klen, strings[10], search[10]);
        findandpatch(kbuf, klen, strings[11], search[11]);
        findandpatch(kbuf, klen, strings[12], search[12]);
        findandpatch(kbuf, klen, strings[13], search[13]);
        findandpatch(kbuf, klen, strings[14], search[14]);
        findandpatch(kbuf, klen, strings[15], search[15]);
        findandpatch(kbuf, klen, strings[16], search[16]);
        findandpatch(kbuf, klen, strings[17], search[17]);
        findandpatch(kbuf, klen, strings[18], search[18]);
        if (version <= 3789){
            printf("[*] Skipping patch: %s string\n", strings[19]);
            printf("%s: quitting...\n", __FUNCTION__);
            return 0;
        }   
        
        int version = atoi(xnu+11);
        if (version == 4570.2) { 
            str_stuff = memmem(kbuf,klen,search[19],strlen(search[19]));
            if (!str_stuff) {
                printf("[-] Failed to find %s string\n", strings[19]);
                
            } 
        } else {
            str_stuff = memmem(kbuf,klen,search[20],strlen(search[20]));
            if (!str_stuff) {
                printf("[-] Failed to find %s string\n", strings[19]);
                
            }
        }
    
        xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
        beg_func = bof64(kbuf,0,xref_stuff);

        *(uint32_t *) (kbuf + beg_func) = 0x52800000;
        *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

        printf("[+] Patched %s\n", strings[19]);
        printf("%s: quitting...\n", __FUNCTION__);
    }
	return 0;
}

int main(int argc, char* argv[]) {
   if(argc < 3) {
   	    printf("sepless - tool to patch SEP and AppleKeyStore functions in kernel by @exploit3dguy\n");
        printf("Usage: %s kcache.raw kcache.pwn [-d]\n", argv[0]);
        printf("       -d for dev kernels\n");
        return 0;
    }

    printf("%s: Starting...\n", __FUNCTION__);

    char *in = argv[1];
	char *out = argv[2];

	void* kbuf;
    size_t klen;

    FILE* fp = fopen(in, "rb");
    if (!fp) {
        printf("[-] Failed to open kernel\n");
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    klen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    kbuf = (void*)malloc(klen);
    if(!kbuf) {
        printf("[-] Out of memory\n");
        fclose(fp);
        exit(1);
    }
    fread(kbuf, 1, klen, fp);
    fclose(fp);

    for(int i = 1; i < argc; i++) {
        if(strncmp(argv[i],"-d",2) == 0) {
            printf("DEVELOPMENT kernelcache inputted\n");
            dev_kernel = true;
        }
    }

    get_sep_patch(kbuf, klen);
    get_applekeystore_patch(kbuf,klen);

    printf("[*] Writing out patched file to %s\n", out);
    fp = fopen(out, "wb+");
        fwrite(kbuf, 1, klen, fp);
        fflush(fp);
    fclose(fp);
    
    printf("%s: Quitting...\n", __FUNCTION__);
    free(kbuf);
    exit(0);
}
