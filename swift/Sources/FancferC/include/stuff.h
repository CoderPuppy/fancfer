typedef long  int64_t;
typedef int   int32_t;
typedef short int16_t;
typedef unsigned long  uint64_t;
typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned long size_t;
typedef long ssize_t;

#define O_TMPFILE 020200000

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
int statx(int dirfd, const char *pathname, int32_t flags, enum statx_mask mask, struct statx *statxbuf);
int ioctl_ficlone(int dest_fd, int src_fd);
enum renameat2_flags {
	RENAME_NOREPLACE = 1 << 0,
	RENAME_EXCHANGE = 1 << 1
};
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, enum renameat2_flags flags);

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

char *get_current_dir_name(void);
