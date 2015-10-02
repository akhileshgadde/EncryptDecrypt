#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h> /*copy_from_user and copy_to_user*/
#include <linux/slab.h> /*kmalloc*/
#include <linux/namei.h>
#include <linux/fs.h>
#include "xcipher.h"

asmlinkage extern long (*sysptr)(void *arg);

int userArgsCheck(struct args *usr_buf)
{
	if (usr_buf == NULL)
		return -EFAULT;
	
	return 0;
}

int checkCharMemAlloc (char *ptr)
{
	if (!ptr) 
		return -ENOMEM;
	return 0;
}

int CopyFromUser (struct args *usr_buf, struct args *ker_buf)
{
	int err = 0;
	struct filename *file = NULL;
	if((err = userArgsCheck(usr_buf)) != 0)
		goto returnFailure;
	if ((err = copy_from_user(ker_buf, usr_buf, sizeof(struct args)) != 0))
		goto returnFailure;
	file = getname(usr_buf->infile);
	if (!file) {
		err = -EINVAL;
		goto returnFailure;
	}
	ker_buf->infile = kmalloc(strlen(file->name) + 1, GFP_KERNEL);
	if ((err = checkCharMemAlloc(ker_buf->infile)) != 0)
		goto returnFailure;
	strncpy(ker_buf->infile, file->name, strlen(file->name));
	if (ker_buf->infile == NULL) {
		err = -ENOENT;
		goto inputFileFail;
	}
	/* Making sure it's a NULL terminated string */
	ker_buf->infile[strlen(file->name)] = '\0';	
	putname(file);
	file = NULL; /* Use the same variable for next getname calls also */
	if ((file = getname(usr_buf->outfile)) == NULL) {
		err = -EINVAL;
		goto inputFileFail;
	}
	ker_buf->outfile = kmalloc(strlen(file->name) + 1, GFP_KERNEL);
	if ((err = checkCharMemAlloc(ker_buf->infile)) != 0) 
                goto inputFileFail;
	strncpy(ker_buf->outfile, file->name, strlen(file->name) + 1);
	if (ker_buf->outfile == NULL) {
		err = -ENOENT;
		goto outputFileFail;
	}
	/* Making sure it's a NULL terminated string */
        ker_buf->outfile[strlen(file->name)] = '\0';
        putname(file);
	ker_buf->keybuf = kmalloc(usr_buf->keylen + 1, GFP_KERNEL);
        if ((err = checkCharMemAlloc(ker_buf->keybuf)) != 0)
                goto outputFileFail;
	if ((err = copy_from_user(ker_buf->keybuf, usr_buf->keybuf, usr_buf->keylen)) != 0)
                goto keybufFail;
	ker_buf->keybuf[usr_buf->keylen] = '\0';

keybufFail:
	kfree(ker_buf->keybuf);
outputFileFail:
	kfree(ker_buf->outfile);
inputFileFail:
	kfree(ker_buf->infile);
returnFailure:
	return err;
}

asmlinkage long xcrypt(void *arg)
{
	int ret;
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	struct args *ker_buf;
	ker_buf = kmalloc(sizeof(struct args), GFP_KERNEL);
	if (!ker_buf) {
		ret = -ENOMEM;
		goto endReturn; //to be corrected
	}
	memset(ker_buf, 0, sizeof(struct args));
	if ((ret = CopyFromUser(arg, ker_buf)) != 0)
		goto copyFail;
	printk("KERN: Input file: %s\n", ker_buf->infile);
	printk("KERN: Output file: %s\n", ker_buf->outfile);
	printk("KERN: Keybuf: %s\n", ker_buf->keybuf);
copyFail:
	kfree(ker_buf);
endReturn:
	return ret;
}

static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
