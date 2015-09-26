#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/uaccess.h> /*copy_from_user and copy_to_user*/
#include <linux/slab.h> /*kmalloc*/
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include "xcipher.h"

static const u8 *aes_iv = (u8 *)XCRYPT_AES_IV;

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

int checkFilePathMax (const char *path)
{
	if (strlen(path) > PATH_MAX)
		return -EINVAL;
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
	if ((err = checkFilePathMax(file->name)) != 0) 
		goto returnFailure;
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
	if ((err = checkFilePathMax(file->name)) != 0)
		goto inputFileFail;
	
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

	//printk("KERN: usrbuf_keybuf: %s, keylen: %d\n", usr_buf->keybuf, usr_buf->keylen);	
	ker_buf->keybuf = kmalloc(usr_buf->keylen + 1, GFP_KERNEL);
        if ((err = checkCharMemAlloc(ker_buf->keybuf)) != 0)
                goto outputFileFail;
	if ((err = copy_from_user(ker_buf->keybuf, usr_buf->keybuf, usr_buf->keylen)) != 0) {
		err = -EFAULT;
                goto keybufFail;
	}
	ker_buf->keybuf[usr_buf->keylen] = '\0';
	return err;
keybufFail:
	if (ker_buf->keybuf)
		kfree(ker_buf->keybuf);
outputFileFail:
	if (ker_buf->outfile)
		kfree(ker_buf->outfile);
inputFileFail:
	if (ker_buf->infile)
		kfree(ker_buf->infile);
returnFailure:
	return err;
}

struct file* open_Input_File(const char *filename, int *err)
{
	struct file *filp = NULL;
	if (filename == NULL) {
		*err = -EBADF;
		goto returnFailure;
	}
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
	if (filename == NULL) {
		*err = -EBADF;
		goto returnFailure;
	}
	filp = filp_open(filename, O_WRONLY | O_CREAT | O_TRUNC, mode);
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


int read_input_file(struct file *filp, void *buf, size_t len)
{
	mm_segment_t oldfs;
	int bytes = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	bytes = vfs_read(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);
	printk("KERN: Bytes read: %d\n", bytes);
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
        printk("KERN: Bytes written: %d\n", bytes);
        return bytes;
}

/* Encryption function has been copied from linux/net/ceph/crypto.c (ceph_aes_encrypt) and made a few modifications to suit our system call. Code credits go to the original author of the file */
static struct crypto_blkcipher *xcrypt_crypto_alloc_cipher(void)
{
	return crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
}

static int xcrypt_aes_encrypt(const void *key, int key_len, void *dst_buf, 
			      size_t dst_len, const void *src_buf, size_t src_len)
{
	struct scatterlist sg_in[1], sg_out[1];
	struct crypto_blkcipher *tfm = xcrypt_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	int ret = 0;
	void *iv;
	int ivsize;
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	dst_len = src_len;
	
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_in, src_buf, src_len);
	sg_set_buf(sg_out, dst_buf, dst_len);
	//ret = setup_sgtable(&sg_out, &prealloc_sg, dst_buf, dst_len);
	//if (ret)
	//	goto out_tfm;
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	iv =  crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);
	ret = crypto_blkcipher_encrypt (&desc, sg_out, sg_in, src_len);
	if (ret < 0) {
		printk("KERN: xcrypt_aes_encrypt failed %d\n", ret);
		goto out_tfm;
	}

out_tfm:
	crypto_free_blkcipher(tfm);
	return ret;
}

/* Decryption function has been copied from linux/net/ceph/crypto.c (ceph_aes_decrypt) and made a few modifications to suit our system call. Code credits go to the original author of the file */

static int xcrypt_aes_decrypt(const void *key, int key_len, void *dst_buf,
			      size_t dst_len, const void *src_buf, size_t src_len)
{
	struct scatterlist sg_out[1], sg_in[1];
	struct crypto_blkcipher *tfm = xcrypt_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm };
	void *iv;
	int ivsize;
	int ret = 0;
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_in, src_buf, src_len);
	sg_set_buf(sg_out, dst_buf, dst_len);
	//ret = setup_sgtable(&sg_in, &prealloc_sg, src_buf, src_len);
	//if (ret)
	//	goto out_tfm;
	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);
	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
	if (ret < 0) {
		printk("KERN: xcrypt_aes_decrypt failed %d\n", ret);
		goto out_tfm;
	}

out_tfm:
	crypto_free_blkcipher(tfm);
	return ret;
}	

void print_md5_hash(unsigned char *keybuf)
{
	int i;
	printk("KERN: MD5 HASH: ");
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		printk("%02x", keybuf[i]);
	printk("\n");
}

/* 
*  Function to calculate the MD5 hash of the given key. 
*  The function prototype is based on example given in Linux documentation at 
*  /usr/src/hw1-USER/Documentation/crypto/api-intro.txt and nfs4_make_rec_clidname 
*  function in linux/source/fs/nfsd/nfsrecover.c 
*/

int calculate_md5_hash (char *inp_key, int keylen, char *md5_hash)
{
	int ret = 0;
	struct scatterlist sg[1];
	struct crypto_hash *tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_TYPE_HASH);
	struct hash_desc desc = { .tfm = tfm, .flags = 0 };
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	ret = crypto_hash_init(&desc);
	if (ret != 0) {
		ret = -EFAULT;
		goto freehash;
	}
	sg_init_table(sg, 1);
	sg_set_buf(sg, inp_key, keylen);
	
	if((ret = crypto_hash_digest(&desc, sg, 1, md5_hash)) != 0) {
		ret = -EFAULT;
		goto freehash;	
	}
freehash:
	crypto_free_hash(tfm);
	return ret;		
}

#if 0
int file_rename(struct file *tmp_filp, struct file *out_filp)
{
	
}
#endif

asmlinkage long xcrypt(void *arg)
{
	int ret;
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	struct args *ker_buf;
	struct file *in_filp = NULL;
	struct file *tmp_filp = NULL;
	struct file *out_filp = NULL;
	char *tmp_file;
	int bytes_read = 0;
	int bytes_written = 0;
	char *read_buf;
	int cmp = 0;
	char *write_buf;
	char *md5_hash;
	ker_buf = kmalloc(sizeof(struct args), GFP_KERNEL);
	if (!ker_buf) {
		ret = -ENOMEM;
		goto endReturn; //to be corrected
	}
	memset(ker_buf, 0, sizeof(struct args));
	if ((ret = CopyFromUser(arg, ker_buf)) != 0)
		goto copyFail;
	/* Open input and output files for reading and writing respectively */
	if ((in_filp = open_Input_File(ker_buf->infile, &ret)) == NULL) {
		if (ret == -EACCES)
			goto closeInputFile;
		else
			goto copyFail;
	}
	read_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!read_buf) {
		ret = -ENOMEM;
		goto closeInputFile;
	}
	write_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!write_buf) {
		ret = -ENOMEM;
		goto freeReadBuf;
	}
	md5_hash = kmalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	if (!md5_hash) {
		ret = -ENOMEM;
		goto freewritebuf;
	}
	tmp_file = kmalloc(strlen(ker_buf->infile) + TEMP_FILE_ADD_SIZE, GFP_KERNEL);
	if (!tmp_file) {
		ret = -ENOMEM;
		goto freemd5hash;
	}
	/* Filename for the temporary file */
	strcpy(tmp_file, ".");
	strcat(tmp_file, ker_buf->infile);
	strcat(tmp_file, ".tmp");
	printk("KERN: temp file: %s\n", tmp_file);
	/*checking max size of tmp file path */
	if ((ret = checkFilePathMax(tmp_file)) != 0)
		goto freetmpfilename;
	/*Open and write to temp file */
	if ((tmp_filp = open_output_file(tmp_file, &ret, in_filp->f_path.dentry->d_inode->i_mode)) == NULL) {
		if (ret == -EACCES)
			goto closeTmpFile;
		else
			goto freetmpfilename;
	}
	
	/*checking both input and tmp files are same */
	if (in_filp->f_path.dentry->d_inode->i_ino == tmp_filp->f_path.dentry->d_inode->i_ino) {
		ret = -EPERM;
		goto closeTmpFile;
	}
	
	/* Write MD5 Hash to output file if encrypting or read MD5 checksum and verify if decrypting */
	if ((ret = calculate_md5_hash(ker_buf->keybuf, ker_buf->keylen, md5_hash)) != 0) {
		ret = -EFAULT;
		goto closeTmpFile;
	}
	
	if (ker_buf->flags == 1) { /*encryption */
		if ((bytes_written = write_output_file(tmp_filp, md5_hash, AES_BLOCK_SIZE)) != AES_BLOCK_SIZE) {
			ret = -EFAULT;
			goto closeTmpFile;
		}
	} else if (ker_buf->flags == 0) { /* Decryption */
		if ((bytes_read = read_input_file (in_filp, read_buf, AES_BLOCK_SIZE)) != AES_BLOCK_SIZE) {
			ret = -EFAULT;
			goto closeTmpFile;
		}
		else {
			if ((cmp = memcmp((void *)read_buf, (void *)md5_hash, AES_BLOCK_SIZE)) != 0) {
				printk("KERN: Decryption, MD5 hash not matching\n");
				ret = -EINVAL;
				goto closeTmpFile;
			}
		}
	} else {
		ret = -EINVAL;
		goto closeTmpFile;
	}
	/* Read from input file, encrypt/decrypt and write to temp file */
	while ((bytes_read = read_input_file (in_filp, read_buf, PAGE_SIZE)) > 0) {
		/* encryption */
		if (ker_buf->flags == 1)
			ret = xcrypt_aes_encrypt(ker_buf->keybuf, AES_BLOCK_SIZE, write_buf, bytes_read, read_buf, bytes_read);
		else if (ker_buf->flags == 0) /* decryption */
			ret = xcrypt_aes_decrypt(ker_buf->keybuf, AES_BLOCK_SIZE, write_buf, bytes_read, read_buf, bytes_read);
		else {
			ret = -EINVAL;
			goto closeTmpFile;
		}	
		if (ret < 0) {
                	ret = -EFAULT;
                        goto closeTmpFile;
                }
		if ((bytes_written = write_output_file(tmp_filp, write_buf, bytes_read)) == 0) {
			ret = -EINVAL;
			goto closeTmpFile;
		} 
	}
	printk("KERN: Input file: %s\n", ker_buf->infile);
	printk("KERN: Tmp file: %s\n", tmp_file);

closeTmpFile:
	filp_close(tmp_filp, NULL);
freetmpfilename:
	if (tmp_file)
		kfree(tmp_file);
freemd5hash:
	if (md5_hash)
		kfree(md5_hash);
freewritebuf:
	if (write_buf)
		kfree(write_buf);
freeReadBuf:
	if (read_buf)
		kfree(read_buf);
closeInputFile:
	filp_close(in_filp, NULL);
copyFail:
	if (ker_buf->infile)
		kfree(ker_buf->infile);
        if (ker_buf->outfile)
		kfree(ker_buf->outfile);
        if (ker_buf->keybuf)
		kfree(ker_buf->keybuf);
	if (ker_buf)
		kfree(ker_buf);
endReturn:
	return ret;
}

static int __init init_sys_xcrypt(void)
{
	printk("Installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}
static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("Removed sys_xcrypt module\n");
}
module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AKHILESH");
MODULE_DESCRIPTION("New xcrypt() system call implementation for encrypting/decrypting files using AES CTR mode");
