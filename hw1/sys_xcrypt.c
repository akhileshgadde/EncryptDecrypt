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
	int err = 0;
	if ((usr_buf == NULL) || (!access_ok(VERIFY_READ, usr_buf, sizeof(struct args))))
		err = -EFAULT;
	if ((usr_buf->keybuf == NULL) || (!access_ok(VERIFY_READ, usr_buf->keybuf, usr_buf->keylen)))
		err = -EFAULT;
	if ((usr_buf->infile == NULL) || (!access_ok(VERIFY_READ, usr_buf->infile, sizeof(usr_buf->infile))))
		err = -EFAULT;
	if ((usr_buf->outfile == NULL) || (!access_ok(VERIFY_READ, usr_buf->outfile, sizeof(usr_buf->outfile))))
                err = -EFAULT;
	return err;
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
	if ((err = copy_from_user(ker_buf, usr_buf, sizeof(struct args)) != 0)) {
		err = -EFAULT;
		goto returnFailure;
	}
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

	printk("KERN: usrbuf_keybuf: %s, keylen: %d\n", usr_buf->keybuf, usr_buf->keylen);	
	ker_buf->keybuf = kmalloc(usr_buf->keylen + 1, GFP_KERNEL);
        if ((err = checkCharMemAlloc(ker_buf->keybuf)) != 0)
                goto outputFileFail;
	if ((err = copy_from_user(ker_buf->keybuf, usr_buf->keybuf, usr_buf->keylen)) != 0) {
		err = -EFAULT;
                goto keybufFail;
	}
	printk("KERN: copy_from_user keybuf ret value: %d\n", err);
	ker_buf->keybuf[usr_buf->keylen] = '\0';
	printk("KERN: Usr_buf->keybuf: %s, ker_buf->keybuf: %s\n", usr_buf->keybuf, ker_buf->keybuf);
keybufFail:
	kfree(ker_buf->keybuf);
outputFileFail:
	kfree(ker_buf->outfile);
inputFileFail:
	kfree(ker_buf->infile);
returnFailure:
	return err;
}

struct file* open_Input_File(const char *filename, int *err)
{
	struct file *filp = NULL;
	if (filename == NULL)
		goto returnFailure;
	filp = filp_open(filename, O_EXCL | O_RDONLY, 0);
	if (!filp || IS_ERR(filp)) {
                printk("KERN: Inputfile read error %d\n", (int) PTR_ERR(filp));
                *err = -ENOENT;
		filp = NULL;
		goto returnFailure;
        }
	if ((!filp->f_op) || (!filp->f_op->read)) {
		printk("KERN: No Read permission on Input file %d\n", (int) PTR_ERR(filp));
		*err = -EACCES;
		filp = NULL;
                goto returnFailure;
	}
	filp->f_pos = 0;
returnFailure:
	return filp;
}

struct file* open_output_file(const char *filename, int *err, umode_t mode)
{
	struct file *filp = NULL;
	if (filename == NULL)
		goto returnFailure;
	filp = filp_open(filename, O_WRONLY | O_CREAT, mode);
	if (!filp || IS_ERR(filp)) {
                printk("KERN: Outputfile write error %d\n", (int) PTR_ERR(filp));
                *err = -ENOENT;
		filp = NULL;
		goto returnFailure;
        }
	if ((!filp->f_op) || (!filp->f_op->write)) {
		printk("KERN: No write permission on Output file %d\n", (int) PTR_ERR(filp));
                *err = -EACCES;
		filp = NULL;
		goto returnFailure;
	}
	filp->f_pos = 0;
returnFailure:
	return filp;
}


int read_input_file(struct file *filp, void *buf)
{
	mm_segment_t oldfs;
	int bytes = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_read(filp, buf, PAGE_SIZE, &filp->f_pos);
	set_fs(oldfs);
	printk("Bytes read: %d\n", bytes);
	return bytes;
}


int write_output_file(struct file *filp, void *buf, int size)
{
	mm_segment_t oldfs;
	int bytes = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_write(filp, buf, size, &filp->f_pos);
	set_fs(oldfs);
        printk("Bytes written: %d\n", bytes);
        return bytes;
}

asmlinkage long xcrypt(void *arg)
{
	int ret;
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	struct args *ker_buf;
	struct file *in_filp = NULL;
	struct file *out_filp = NULL;
	int bytes_read = 0;
	int bytes_written = 0;
	char *read_buf;
	ker_buf = kmalloc(sizeof(struct args), GFP_KERNEL);
	if (!ker_buf) {
		ret = -ENOMEM;
		goto endReturn; //to be corrected
	}
	memset(ker_buf, 0, sizeof(struct args));
	if ((ret = CopyFromUser(arg, ker_buf)) != 0)
		goto copyFail;
	printk("KERN: Ret after copy_from_user %d\n", ret);
	/* Open input and output files for reading and writing respectively */
	if ((in_filp = open_Input_File(ker_buf->infile, &ret)) == NULL)
		goto endReturn;
	if (ret == -EACCES)
		goto closeInputFile;
	read_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!read_buf) {
		ret = -ENOMEM;
		goto endReturn;
	}
	if ((out_filp = open_output_file(ker_buf->outfile, &ret, in_filp->f_path.dentry->d_inode->i_mode)) == NULL)
		goto endReturn;
	if (ret == -EACCES)
		goto closeOutputFile;
	/*checking both input and output files are same */
	if (in_filp->f_path.dentry->d_inode->i_ino == out_filp->f_path.dentry->d_inode->i_ino) {
		ret = -EPERM;
		goto closeOutputFile;
	}
	while ((bytes_read = read_input_file (in_filp, read_buf)) > 0) {
		if ((bytes_written = write_output_file(out_filp, read_buf, bytes_read)) == 0) {
			ret = -EINVAL;
			goto closeOutputFile;
		} 
	}
	printk("KERN: Input file: %s\n", ker_buf->infile);
	printk("KERN: Output file: %s\n", ker_buf->outfile);
	printk("KERN: Keybuf: %s\n", ker_buf->keybuf);

closeOutputFile:
	filp_close(out_filp, NULL);
closeInputFile:
	filp_close(in_filp, NULL);
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
