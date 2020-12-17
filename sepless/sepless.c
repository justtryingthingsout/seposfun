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

int get_sep_patch(void* kbuf,size_t klen) {

	

    if (dev_kernel == true) {
    	xnu = memmem(kbuf,klen,"root:xnu_",9);
        version = atoi(xnu+20);

    }
    else {
    xnu = memmem(kbuf,klen,"root:xnu-",9);
    version = atoi(xnu+9);
   }


    if (version <= 4570) {
    printf("getting %s()\n", __FUNCTION__);

	str_stuff = memmem(kbuf,klen,"void AppleSEPFirmware::_initFromMemory",38);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPFirmware initFromMemory string\n");
    	return -1;
    }
    
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPFirmware initFromMemory\n");

    str_stuff = memmem(kbuf,klen,"IOReturn AppleSEPManager::setFirmwareBytes",42);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPManager setFirmwareBytes string\n");
    	return -1;
    }
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPManager setFirmwareBytes\n");


    str_stuff = memmem(kbuf,klen,"void AppleSEPBooter::_bootAction",32);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPBooter bootAction string\n");
    	return -1;
    }
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPBooter bootAction\n");

    str_stuff = memmem(kbuf,klen,"IOReturn AppleSEPBooter::bootSEP",32);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPBooter bootSEP string\n");
    	return -1;
    }
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPBooter bootSEP\n");
    
    printf("%s: quitting...\n", __FUNCTION__);
    

    }

	return 0;
}

int get_applekeystore_patch(void *kbuf, size_t klen) {

	if (dev_kernel == true) {
    	xnu = memmem(kbuf,klen,"root:xnu_",9);
        version = atoi(xnu+20);

    }
    else {
    xnu = memmem(kbuf,klen,"root:xnu-",9);
    version = atoi(xnu+9);
   }


    if (version <= 4570) {

	printf("getting %s()\n", __FUNCTION__);

    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: Failed to prepare output memory descriptor.",65);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore failed to prepare output memory descriptor string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore failed to prepare output memory descriptor\n");
     
    str_stuff = memmem(kbuf,klen,"AppleKeyStore starting",22);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleKeyStore starting string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleKeyStore starting\n");

    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: Failed to initialize _workLoop",52);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore failed to initialize workLoop string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore failed to initialize workLoop\n");

    if (version <= 3789){

    	printf("[*] Skipping patch: AppleSEPKeyStore sep_enabled\n");

    }

    else {

    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: _sep_enabled",34); // 11.x stuff
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore sep_enabled string\n");
    	return -1;
    }
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore sep_enabled\n");
   }

    
    if (version <= 3789){

    	printf("[*] Skipping patch: AppleSEPKeyStore volume keybags\n");

    }

    else {
    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: -- Volume keybags:",40); // 11.x stuff
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore volume keybags string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore volume keybags\n");
   }

    


    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s:  %s : %4d (%08x)",38);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore 4d string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore 4d\n");
   
    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: ----------------",38);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore ---------------- string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore ----------------\n");

    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: vfs notification failed",45);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore vfs notification failed string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore vfs notification failed\n");


    str_stuff = memmem(kbuf,klen,"AppleKeyStore: Sending lock change %d",37);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleKeyStore Sending lock change string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleKeyStore Sending lock change\n");
 
    str_stuff = memmem(kbuf,klen,"AppleKeyStore: stash expired",28);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleKeyStore stash expired string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleKeyStore stash expired change\n");

    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: keybagd has not registered",48);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore keybagd has not registered string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore keybagd has not registered\n");
    
    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: failed to notify system keybag updation",61);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore failed to notify system keybag updation string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore failed to notify system keybag updation\n");

    str_stuff = memmem(kbuf,klen,"\x41\x70\x70\x6C\x65\x53\x45\x50\x4B\x65\x79\x53\x74\x6F\x72\x65\x3A\x3A\x25\x73\x3A\x20\x66\x61\x69\x6C\x65\x64\x20\x74\x6F\x20\x6E\x6F\x74\x69\x66\x79\x20\x25\x64\x0A\x00\x74\x69\x63\x6B\x6C\x65\x5F\x62\x61\x63\x6B\x75\x70\x5F\x6E\x6F\x74\x69\x66\x79\x5F\x70\x6F\x72\x74",0x44);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore failed to notify tickle_backup_notify_por string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore failed to notify tickle_backup_notify_por\n");
    
    if (version <= 3789){

    	printf("[*] Skipping patch: mapping volume without a cookie\n");

    }
    else {
    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: Mapping volume without",44);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore mapping volume without a cookie string\n");
    	return -1;
    }

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore mapping volume without a cookie\n");
    }
    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: Volume cookie mismatch",44);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore volume cookie mismatch string\n");
    	return -1;
    } 

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore volume cookie mismatch\n");

    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: unmapped uuid",35);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore unmapped uuid string\n");
    	return -1;
    } 

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore unmapped uuid\n");

    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: mapped uuid",33);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore mapped uuid string\n");
    	return -1;
    } 

    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore mapped uuid\n");
    

     if (version <= 3789){

     	printf("[*] Skipping patch: AppleSEPKeyStore notified volume uuid - locked string\n");

     }

    else {
    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: notified volume uuid %s - locked",54);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore notified volume uuid - locked string\n");
    	return -1;
    } 
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore notified volume uuid - locked\n");
}


    if (version <= 3789){

    	printf("[*] Skipping patch: AppleSEPKeyStore notified volume uuid - lock state\n");

    }   
    else {
    str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: notified volume uuid %s - lock state",58);
    if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore notified volume uuid - lock state string\n");
    	return -1;
    } 


    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore notified volume uuid - lock state\n");
}
    if (version <= 3789){

    	printf("[*] Skipping patch: AppleSEPKeyStore can't find AppleSEPManager string\n");
    	printf("%s: quitting...\n", __FUNCTION__);
    	return 0;

    }   
     
    int version = atoi(xnu+11);
    



    if (version == 4570.2) { 
        str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: ::sep_endpoint() can't find AppleSEPManager",65);
        if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore can't find AppleSEPManager string\n");
    	return -1;
      } 
    }

    else {
    	str_stuff = memmem(kbuf,klen,"AppleSEPKeyStore::%s: Can't find AppleSEPManager",48);
        if (!str_stuff) {
    	printf("[-] Failed to find AppleSEPKeyStore can't find AppleSEPManager string\n");
    	return -1;
    }
    }
 
    xref_stuff = xref64(kbuf,0,klen,(addr_t)GET_OFFSET(klen, str_stuff));
    
    beg_func = bof64(kbuf,0,xref_stuff);

     

    *(uint32_t *) (kbuf + beg_func) = 0x52800000;
    *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

    printf("[+] Patched AppleSEPKeyStore can't find AppleSEPManager\n");
 
    printf("%s: quitting...\n", __FUNCTION__);

}


	return 0;
}


int main(int argc, char* argv[]) {

   
   
   if(argc < 3) {
   	    printf("sepless - tool to patch SEP and AppleKeyStore functions in kernel by @exploit3dguy\n");
        printf("Usage: kcache.raw kcache.pwn [-d]\n");
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
     	return -1;
     }

    fseek(fp, 0, SEEK_END);
    klen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    kbuf = (void*)malloc(klen);
    if(!kbuf) {
        printf("[-] Out of memory\n");
        fclose(fp);
        return -1;
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

    fp = fopen(out, "wb+");

    fwrite(kbuf, 1, klen, fp);
    fflush(fp);
    fclose(fp);
    
    free(kbuf);

    printf("[*] Writing out patched file to %s\n", out);

    printf("%s: Quitting...\n", __FUNCTION__);

   return 0;

}
