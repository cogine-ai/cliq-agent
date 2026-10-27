#define _GNU_SOURCE
/* A real owned Linux user/mount/PID-namespace component for the fixed recipe's
 * pre-READY RO view + private RW-directory capability separation. No Run,
 * native producer receipt, system unit or installed qualification is made. */
#if defined(__linux__)
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static void text_file(const char *path,const char *text){int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);assert(fd>=0);size_t size=strlen(text);assert(write(fd,text,size)==(ssize_t)size);assert(!close(fd));}
static void drop_capabilities(void){
    assert(!prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));assert(!prctl(PR_SET_DUMPABLE,0,0,0,0));
    assert(!prctl(PR_SET_SECUREBITS,SECBIT_NOROOT|SECBIT_NOROOT_LOCKED|SECBIT_NO_SETUID_FIXUP|SECBIT_NO_SETUID_FIXUP_LOCKED,0,0,0));
    assert(!prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0));
    for(unsigned cap=0;cap<64;cap++){errno=0;int result=prctl(PR_CAPBSET_DROP,cap,0,0,0);assert(result==0 || (result<0 && errno==EINVAL));}
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct data[2]={{0},{0}};
    assert(!syscall(SYS_capset,&header,data));assert(!syscall(SYS_capget,&header,data));
    assert(!data[0].effective && !data[0].permitted && !data[0].inheritable && !data[1].effective && !data[1].permitted && !data[1].inheritable);
    for(unsigned cap=0;cap<64;cap++){errno=0;int result=prctl(PR_CAPBSET_READ,cap,0,0,0);assert(result==0 || (result<0 && errno==EINVAL));}
}
static void path_is_readonly(void){
    const char *paths[]={"/scratch/package-cache/mutate","/scratch/package-cache/../package-cache/mutate","/scratch/../scratch/package-cache/mutate"};
    for(size_t i=0;i<sizeof(paths)/sizeof(paths[0]);i++){errno=0;int fd=open(paths[i],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(fd<0 && errno==EROFS);}
    errno=0;assert(link("/scratch/package-cache/blob.tgz","/scratch/link-escape")<0 && (errno==EXDEV || errno==EROFS));
    errno=0;assert(rename("/scratch/package-cache/blob.tgz","/scratch/rename-escape")<0 && (errno==EXDEV || errno==EROFS));
    errno=0;assert(mount("/scratch/package-cache","/scratch/package-cache",NULL,MS_REMOUNT|MS_BIND,NULL)<0 && errno==EPERM);
}
static int namespace_init(const char *home){
    assert(getpid()==1);assert(!mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));
    assert(!mount("tmpfs",home,"tmpfs",MS_NOSUID|MS_NODEV,"size=1048576,mode=0700"));
    char path[PATH_MAX];const char *directories[]={"scratch","scratch/package-cache","proc","tmp"};
    for(size_t i=0;i<sizeof(directories)/sizeof(directories[0]);i++){assert(snprintf(path,sizeof(path),"%s/%s",home,directories[i])>0);assert(!mkdir(path,0700));}
    assert(snprintf(path,sizeof(path),"%s/proc",home)>0);assert(!mount("proc",path,"proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL));
    assert(!chroot(home));assert(!chdir("/"));
    int root=open("/scratch/package-cache",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);assert(root>=0);struct stat original,current;assert(!fstat(root,&original));
    assert(!mount("/scratch/package-cache","/scratch/package-cache",NULL,MS_BIND,NULL));
    assert(!mount(NULL,"/scratch/package-cache",NULL,MS_REMOUNT|MS_BIND|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL));
    int channels[2][2];assert(!pipe2(channels[0],O_CLOEXEC));assert(!pipe2(channels[1],O_CLOEXEC));
    drop_capabilities();pid_t child=fork();assert(child>=0);
    if(!child){
        assert(getpid()==2 && getppid()==1);assert(!close(channels[0][0]));assert(!close(channels[1][1]));
        int report=fcntl(channels[0][1],F_DUPFD_CLOEXEC,10),barrier=fcntl(channels[1][0],F_DUPFD_CLOEXEC,10);assert(report>=10 && barrier>=10);
        assert(dup2(report,3)==3 && dup2(barrier,4)==4);assert(!syscall(SYS_close_range,5,UINT_MAX,0));
        for(int fd=5;fd<64;fd++){errno=0;assert(fcntl(fd,F_GETFD)<0 && errno==EBADF);}
        struct stat descriptor;for(int fd=0;fd<5;fd++)if(!fstat(fd,&descriptor))assert(!S_ISDIR(descriptor.st_mode));
        char parent_capability[96];assert(snprintf(parent_capability,sizeof(parent_capability),"/proc/1/fd/%d",root)>0);
        errno=0;assert(open(parent_capability,O_RDONLY|O_DIRECTORY|O_CLOEXEC)<0 && (errno==EACCES || errno==EPERM));
        errno=0;assert(open("/proc/1/root",O_RDONLY|O_DIRECTORY|O_CLOEXEC)<0 && (errno==EACCES || errno==EPERM));
        char observed='B';assert(write(3,&observed,1)==1);assert(read(4,&observed,1)==1 && observed=='V');
        path_is_readonly();assert(write(3,"S",1)==1);assert(read(4,&observed,1)==1 && observed=='R');
        assert(!close(4));path_is_readonly();int effect=open("/tmp/started-after-seal",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);assert(effect>=0);
        assert(write(effect,"usercode",8)==8 && !close(effect));assert(write(3,"D",1)==1 && !close(3));_exit(0);
    }
    assert(!close(channels[0][1]));assert(!close(channels[1][0]));char observed;assert(read(channels[0][0],&observed,1)==1 && observed=='B');
    assert(lstat("/tmp/started-after-seal",&current)<0 && errno==ENOENT);
    int writer=openat(root,"blob.tgz",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);assert(writer>=0);
    assert(write(writer,"original-payload",16)==16 && !fchmod(writer,0400) && !close(writer));
    assert(!fstat(root,&current) && current.st_dev==original.st_dev && current.st_ino==original.st_ino);
    int readonly=open("/scratch/package-cache/blob.tgz",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);assert(readonly>=0);char bytes[17]={0};
    assert(read(readonly,bytes,sizeof(bytes))==16 && !strcmp(bytes,"original-payload") && read(readonly,bytes,1)==0 && !close(readonly));
    assert(write(channels[1][1],"V",1)==1);assert(read(channels[0][0],&observed,1)==1 && observed=='S');
    assert(lstat("/tmp/started-after-seal",&current)<0 && errno==ENOENT);
    assert(!close(root));errno=0;assert(fcntl(root,F_GETFD)<0 && errno==EBADF);
    assert(write(channels[1][1],"R",1)==1 && !close(channels[1][1]));assert(read(channels[0][0],&observed,1)==1 && observed=='D');
    assert(read(channels[0][0],&observed,1)==0 && !close(channels[0][0]));int status;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    assert(!lstat("/tmp/started-after-seal",&current) && current.st_size==8);return 0;
}
int main(void){
    char home[]="/tmp/cliq-dependency-boundary-XXXXXX";assert(mkdtemp(home));uid_t uid=getuid();gid_t gid=getgid();pid_t setup=fork();assert(setup>=0);
    if(!setup){assert(!unshare(CLONE_NEWUSER|CLONE_NEWNS));char mapping[96];assert(snprintf(mapping,sizeof(mapping),"0 %lu 1\n",(unsigned long)uid)>0);text_file("/proc/self/uid_map",mapping);
        text_file("/proc/self/setgroups","deny");assert(snprintf(mapping,sizeof(mapping),"0 %lu 1\n",(unsigned long)gid)>0);text_file("/proc/self/gid_map",mapping);
        assert(!unshare(CLONE_NEWPID));pid_t init=fork();assert(init>=0);if(!init)_exit(namespace_init(home));int status;
        assert(waitpid(init,&status,0)==init && WIFEXITED(status) && WEXITSTATUS(status)==0);_exit(0);}
    int status;assert(waitpid(setup,&status,0)==setup && WIFEXITED(status) && WEXITSTATUS(status)==0);assert(!rmdir(home));
    puts("{\"component\":\"dependency-private-ro-view-rw-capability\",\"bothCapsDroppedBeforeBlocked\":true,\"childDescriptorPruned\":true,\"parentProcDenied\":true,\"pathParentRenameHardlinkReadOnly\":true,\"writerAndOriginalDirectoryJoinedBeforeRelease\":true,\"allProcessesAndPipesJoined\":true,\"installedQualification\":false}");return 0;
}
#else
#include <stdio.h>
int main(void){puts("{\"component\":\"dependency-private-ro-view-rw-capability\",\"supported\":false,\"installedQualification\":false}");return 77;}
#endif
