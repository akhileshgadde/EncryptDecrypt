#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <openssl/md5.h>
#include <unistd.h>
#include "xcipher.h"

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif
void readargs(int argc, char *argv[], struct args *send_buf);
void print_usage();

int main(int argc, char *argv[])
{
	int rc = 0;
	struct args *send_buf = (struct args *) malloc(sizeof(struct args));
	if (!send_buf) {
		rc = -ENOMEM;
		goto end;
	}
	//void *dummy = (void *) argv[1];
	readargs(argc, argv, send_buf);
  	rc = syscall(__NR_xcrypt, (void *)send_buf);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d, Error: %s)\n", rc, errno, strerror(errno));
	if (send_buf->infile)
		free(send_buf->infile);
	if (send_buf->outfile)
		free(send_buf->outfile);
	if (send_buf->keybuf)
		free(send_buf->keybuf);
	if (send_buf)
		free(send_buf);
end:
	exit(rc);
}

void readargs (int argc, char *argv[], struct args *send_buf)
{
	int opt = 0;
	int encr_flag = 0, decr_flag = 0, help_flag = 0; 
	unsigned char md5_hash[MD5_DIGEST_LENGTH];
	int len;
	opterr = 0;
	while ((opt = getopt(argc, argv, "edc:p:h")) != -1) {
		switch (opt) {
		case 'e':
			encr_flag = 1;
			send_buf->flags = 1;
			break;
		case 'd':
			decr_flag = 1;
			send_buf->flags = 0;
			break;
		case 'c':
			printf("Type of Cipher: %s\n", optarg);
			printf("Len: %d\n", strlen(optarg));
			break;
		case 'p':
			send_buf->keybuf = (char *) malloc(MD5_DIGEST_LENGTH);
			if (!send_buf) {
				printf("Malloc: No Memory\n");
				goto failend;
			}
			MD5((const unsigned char *) optarg, strlen(optarg), md5_hash);
			send_buf->keylen = MD5_DIGEST_LENGTH;
			//printf("MD5_DIGEST_LEN: %d\n", MD5_DIGEST_LENGTH);
			#if 0
			printf("MD5 Hash: \n");
			for (i = 0; i < 16; i++)
				printf("%02x", md5_hash[i]);
			printf("\n");
			#endif
			memcpy(send_buf->keybuf, md5_hash, MD5_DIGEST_LENGTH);
			send_buf->keybuf[MD5_DIGEST_LENGTH] = '\0';
			break;
		case 'h':
			help_flag = 1;
			print_usage();
			break;
		case '?':
			if (optopt == 'p')
				printf("Option -p requires an argument\n");
			else
				printf("Invalid option '-%c' specified\n", optopt);
			exit(EXIT_FAILURE);
		default:
			exit(EXIT_FAILURE);
		}
	}
		if ((encr_flag == 1) && (decr_flag == 1)) {
			printf("Can perform only encryption or decryption at a time\n");
			exit(EXIT_FAILURE);
		}
		else if ((encr_flag == 0) && (decr_flag == 0)) {
			printf("No Encryption/Decryption specified.\n");
			exit(EXIT_FAILURE);
		}
		if (optind < argc) {
			len = strlen(argv[optind]);
			send_buf->infile = (char *) malloc(len);
			if (!send_buf) {
				printf("Malloc: No memory\n");
				goto freekeybuf;
			}
			strncpy(send_buf->infile, argv[optind], len+1);
			optind++;
			if (optind >= argc) {
				printf("Output file not specified\n");
				exit (EXIT_FAILURE);
			}
			len = strlen(argv[optind]);
			send_buf->outfile = (char *) malloc(len);
			if (!send_buf) {
				printf("Malloc: No memory\n");
				goto freeinfile;
			}
                        strncpy(send_buf->outfile, argv[optind], len+1);
			optind++;
			if (optind < argc) {
				printf("Un-recognizable arguments after filenames\n");
                        	exit (EXIT_FAILURE);
			}
			//printf("input file: %s\n", send_buf->infile);
			//printf("output file: %s\n", send_buf->outfile);
		} else if (help_flag == 0) {
			printf("Input and Output file names not specified\n");
			exit (EXIT_FAILURE);
		}
	return;

freeinfile:
	free(send_buf->infile);
freekeybuf:
	free(send_buf->keybuf);
failend:
	exit(EXIT_FAILURE);
}

void print_usage()
{
	printf("Correct usage: ./xhw1 [-e/-d] [-h] [-c ARG] [-p ARG] <input-file> <output-file>\n");
        printf("[-e/-d]: -e for encryption and -d for decryption\n");
        printf("[-h]: -h for help with the options\n");
        printf("[-c ARG]: -c to sepecify the type of cipher. Default 'AES' is used.(option  not supported at this point, AES is the default encryption mechanism)\n");
        printf("[-p ARG]: -p to specify the key\n");
        printf("<input-file>: Specify any existent valid UNIX input file name\n");
        printf("<output-file>: Specify any valid UNIX output file name\n");
}

