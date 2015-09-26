#define AES_BLOCK_SIZE 16
#define XCRYPT_AES_IV "xcryptakgaddeakgadde"
#define TEMP_FILE_ADD_SIZE 4

struct args {
	char *infile;
	char *outfile;
	char *keybuf;
	int keylen;
	int flags;
};
