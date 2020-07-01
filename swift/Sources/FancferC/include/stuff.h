// #include<stdint.h>
typedef long  int64_t;
typedef int   int32_t;
typedef short int16_t;
typedef unsigned long  uint64_t;
typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned long size_t;
typedef long ssize_t;

void free(void*);
const char *strerror(int errnum);
__thread extern int errno;
#define ENOENT 2
#define EEXIST 17

#define AT_FDCWD -100

typedef struct FILE FILE;
FILE *fdopen(int fd, const char *mode);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fclose(FILE *stream);
int64_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);
int fileno(FILE *stream);
enum fseek_whence {
	SEEK_SET = 0,
	SEEK_CUR = 1,
	SEEK_END = 2
};
int fseek(FILE *stream, long offset, enum fseek_whence whence);
long ftell(FILE *stream);

#define O_RDONLY            00
#define O_WRONLY            01
#define O_RDWR              02
#define O_CREAT           0100
#define O_DIRECTORY    0200000
#define O_PATH       010000000
#define O_TMPFILE   (020000000 | O_DIRECTORY)

#define S_IXOTH  0000001
#define S_IWOTH  0000002
#define S_IROTH  0000004
#define S_IXGRP  0000010
#define S_IWGRP  0000020
#define S_IRGRP  0000040
#define S_IXUSR  0000100
#define S_IWUSR  0000200
#define S_IRUSR  0000400
#define S_ISVTX  0001000
#define S_ISGID  0002000
#define S_ISUID  0004000
#define S_IFMT   0170000
#define S_IFIFO  0010000
#define S_IFCHR  0020000
#define S_IFDIR  0040000
#define S_IFBLK  0060000
#define S_IFREG  0100000
#define S_IFLNK  0120000
#define S_IFSOCK 0140000
int openat(int dirfd, const char *pathname, int flags, int mode);
int close(int fd);
struct statx_timestamp {
	int64_t tv_sec;
	uint32_t tv_nsec;
	int32_t __reserved;
};
enum statx_mask {
	STATX_TYPE        = 0x00000001,
	STATX_MODE        = 0x00000002,
	STATX_NLINK       = 0x00000004,
	STATX_UID         = 0x00000008,
	STATX_GID         = 0x00000010,
	STATX_ATIME       = 0x00000020,
	STATX_MTIME       = 0x00000040,
	STATX_CTIME       = 0x00000080,
	STATX_INO         = 0x00000100,
	STATX_SIZE        = 0x00000200,
	STATX_BLOCKS      = 0x00000400,
	STATX_BASIC_STATS = 0x000007ff,
	STATX_BTIME       = 0x00000800,
	STATX_ALL         = 0x00000fff
};
struct statx {
	uint32_t stx_mask;
	uint32_t stx_blksize;
	uint64_t stx_attributes;
	uint32_t stx_nlink;
	uint32_t stx_uid;
	uint32_t stx_gid;
	uint16_t stx_mode;
	uint16_t __spare0[1];
	uint64_t stx_ino;
	uint64_t stx_size;
	uint64_t stx_blocks;
	uint64_t stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime; // creation
	struct statx_timestamp stx_ctime; // status change
	struct statx_timestamp stx_mtime;
	uint32_t stx_rdev_major;
	uint32_t stx_rdev_minor;
	uint32_t stx_dev_major;
	uint32_t stx_dev_minor;
	uint64_t __spare2[14];
};
enum at_flags {
	AT_SYMLINK_NOFOLLOW = 0x100,
	AT_SYMLINK_FOLLOW = 0x400,
	AT_EMPTY_PATH = 0x1000
};
int statx(int dirfd, const char *pathname, enum at_flags flags, enum statx_mask mask, struct statx *statxbuf);
int64_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsize);
int symlinkat(const char *target, int newdirfd, const char *linkpath);
int ioctl_ficlone(int dest_fd, int src_fd);
enum renameat2_flags {
	RENAME_NOREPLACE = 1 << 0,
	RENAME_EXCHANGE = 1 << 1
};
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, enum renameat2_flags flags);
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, enum at_flags flags);
int unlinkat(int dirfd, const char *pathname, enum at_flags flags);
int mkdirat(int dirfd, const char *pathname, int mode);

int64_t llistxattr(const char *path, char *list, size_t size);
int64_t flistxattr(int fd,           char *list, size_t size);
int64_t lgetxattr(const char *path, const char *name, void *value, size_t size);
int64_t fgetxattr(int fd,           const char *name, void *value, size_t size);
enum setxattr_flags {
	XATTR_CREATE = 1,
	XATTR_REPLACE = 2
};
int lsetxattr(const char *path, const char *name, const void *value, size_t size, enum setxattr_flags flags);
int fsetxattr(int fd,           const char *name, const void *value, size_t size, enum setxattr_flags flags);
int lremovexattr(const char *path, const char *name);
int fremovexattr(int fd,           const char *name);

struct dirent {
	uint64_t d_ino;
	int64_t d_off;
	unsigned short int d_reclen;
	unsigned char d_type;
	char d_name[];
};
typedef struct DIR DIR;
DIR *fdopendir(int fd);
int closedir(DIR *dirp);
struct dirent *readdir(DIR *dirp);
int dirfd(DIR *dirp);
void rewinddir(DIR *dirp);
void seekdir(DIR *dirp, long loc);
long telldir(DIR *dirp);

char *get_current_dir_name(void);
