#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "xcipher.h"

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif
void readargs(int argc, char *argv[], struct args *send_buf);
void print_usage();

typedef struct {
	int encr_flag;
	int decr_flag;
	int help_flag;
	char *keybuf;
}cmd_line_args;

int main(int argc, char *argv[])
{
	int rc = 0;
	struct args *send_buf = (struct args *) calloc(0, sizeof(struct args));
	//void *dummy = (void *) argv[1];
	readargs(argc, argv, send_buf);
  	rc = syscall(__NR_xcrypt, (void *)send_buf);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);
	exit(rc);
}

void readargs (int argc, char *argv[], struct args *send_buf)
{
	int opt = 0;
	//char *result = NULL;
	cmd_line_args *opts;
	int len;
	opts = (cmd_line_args *) malloc (sizeof(cmd_line_args));
	opterr = 0;
	while ((opt = getopt(argc, argv, "edc:p:h")) != -1) {
		switch (opt) {
		case 'e':
			opts->encr_flag = 1;
			send_buf->flags = 1;
			break;
		case 'd':
			opts->decr_flag = 1;
			send_buf->flags = 0;
			break;
		case 'c':
			printf("Type of Cipher: %s\n", optarg);
			printf("Len: %d\n", strlen(optarg));
			break;
		case 'p':
			send_buf->keylen = strlen(optarg);
			send_buf->keybuf = (char *) malloc(send_buf->keylen + 1);
			strncpy(send_buf->keybuf, optarg, send_buf->keylen + 1);
			break;
		case 'h':
			opts->help_flag = 1;
			print_usage();
			break;
		case '?':
			printf("Invalid option '-%c' specified\n", optopt);
			exit(EXIT_FAILURE);
		default:
			exit(EXIT_FAILURE);
		}
	}
		if ((opts->encr_flag == 1) && (opts->decr_flag == 1)) {
			printf("Can perform only encryption or decryption at a time\n");
			exit(EXIT_FAILURE);
		}
		if (optind < argc) {
			len = strlen(argv[optind]);
			send_buf->infile = (char *) malloc(len);
			strncpy(send_buf->infile, argv[optind], len);
			optind++;
			if (optind >= argc) {
				printf("Output file not specified\n");
				exit (EXIT_FAILURE);
			}
			len = strlen(argv[optind]);
			send_buf->outfile = (char *) malloc(len);
                        strncpy(send_buf->outfile, argv[optind], len);
			optind++;
			if (optind < argc) {
				printf("Un-recognizable arguments after filenames\n");
                        	exit (EXIT_FAILURE);
			}
			printf("input file: %s\n", send_buf->infile);
			printf("output file: %s\n", send_buf->outfile);
		} else if (opts->help_flag == 0) {
			printf("Input and Output file names not specified\n");
			exit (EXIT_FAILURE);
		}
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

