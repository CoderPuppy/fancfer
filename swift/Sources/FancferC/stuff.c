#include <sys/ioctl.h>
#include <linux/fs.h>

int ioctl_ficlone(int dest_fd, int src_fd) {
	return ioctl(dest_fd, FICLONE, src_fd);
}
