local ffi = require 'ffi'
local bit = require 'bit'
local pl = require 'pl.import_into' ()

local sha256; do
	ffi.cdef [[
		typedef struct {} EVP_MD_CTX;
		typedef struct {} EVP_MD;
		typedef struct {} ENGINE;
		EVP_MD_CTX *EVP_MD_CTX_new(void);
		void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
		const EVP_MD *EVP_sha256(void);
		int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
		int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, uint32_t *s);
	]]

	local openssl = ffi.load('ssl')

	function sha256()
		local ctx = ffi.gc(openssl.EVP_MD_CTX_new(), openssl.EVP_MD_CTX_free)
		openssl.EVP_DigestInit_ex(ctx, openssl.EVP_sha256(), nil)
		local function pump(data, len)
			if data then
				openssl.EVP_DigestUpdate(ctx, data, len or #data)
				return pump
			else
				local buf = ffi.new('unsigned char[?]', 32)
				local n = ffi.new('int[1]')
				openssl.EVP_DigestFinal_ex(ctx, buf, n)
				assert(n[0] == 32)
				local h = ''
				for i = 0, 31 do
					h = ('%s%02x'):format(h, buf[i])
				end
				return h
			end
		end
		return pump
	end
end
-- print(sha256()('fizbuz\n')())

ffi.cdef [[
	void free(void*);
	const char *strerror(int errnum);
	enum errno {
		ENOENT = 2,
		EEXIST = 17
	};

	typedef struct {} FILE;
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

	enum open_flags {
		O_RDONLY = 00,
		O_WRONLY = 01,
		O_RDWR   = 02,
		O_CREAT = 0100,
		O_DIRECTORY = 0200000,
		O_PATH = 010000000,
		O_TMPFILE = 020000000 | O_DIRECTORY
	};
	enum mode {
		S_IXOTH  = 0000001,
		S_IWOTH  = 0000002,
		S_IROTH  = 0000004,
		S_IXGRP  = 0000010,
		S_IWGRP  = 0000020,
		S_IRGRP  = 0000040,
		S_IXUSR  = 0000100,
		S_IWUSR  = 0000200,
		S_IRUSR  = 0000400,
		S_ISVTX  = 0001000,
		S_ISGID  = 0002000,
		S_ISUID  = 0004000,
		S_IFMT   = 0170000,
		S_IFIFO  = 0010000,
		S_IFCHR  = 0020000,
		S_IFDIR  = 0040000,
		S_IFBLK  = 0060000,
		S_IFREG  = 0100000,
		S_IFLNK  = 0120000,
		S_IFSOCK = 0140000,
	};
	int openat(int dirfd, const char *pathname, enum open_flags flags, enum mode mode);
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
	enum ioctl {
		FICLONE = 1 << 30 | 0x94 << 8 | 9 << 0 | sizeof(int) << 16
	};
	int ioctl(int fd, enum ioctl request, ...);
	enum renameat2_flags {
		RENAME_NOREPLACE = 1 << 0,
		RENAME_EXCHANGE = 1 << 1
	};
	int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, enum renameat2_flags flags);
	int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, enum at_flags flags);
	int unlinkat(int dirfd, const char *pathname, enum at_flags flags);
	int mkdirat(int dirfd, const char *pathname, enum mode mode);

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
	typedef struct {} DIR;
	DIR *fdopendir(int fd);
	int closedir(DIR *dirp);
	struct dirent *readdir(DIR *dirp);
	int dirfd(DIR *dirp);
	void rewinddir(DIR *dirp);
	void seekdir(DIR *dirp, long loc);
	long telldir(DIR *dirp);

	char *get_current_dir_name(void);
]]

local function cerror(errno)
	if not errno then errno = ffi.errno() end
	error(('error: %s [%d]'):format(ffi.string(ffi.C.strerror(errno)), errno), 2)
end

local normal_file_mode = bit.bor(
	ffi.C.S_IROTH, ffi.C.S_IRGRP,
	ffi.C.S_IRUSR, ffi.C.S_IWUSR
)
local normal_dir_mode = bit.bor(
	ffi.C.S_IXOTH, ffi.C.S_IROTH,
	ffi.C.S_IXGRP, ffi.C.S_IRGRP,
	ffi.C.S_IXUSR, ffi.C.S_IRUSR, ffi.C.S_IWUSR
)

local buf = ffi.new('char[?]', 1024)
local function get_buffer(size)
	if size <= ffi.sizeof(buf) then
		return buf
	else
		return ffi.new('char[?]', size)
	end
end

local function fgetxattr(fd, name)
	while true do
		local exp_size = ffi.C.fgetxattr(fd, name, nil, 0)
		if exp_size == -1 then cerror() end
		local buf = get_buffer(exp_size + 1)
		local real_size = ffi.C.fgetxattr(fd, name, buf, ffi.sizeof(buf))
		if real_size == -1 then cerror() end
		if real_size == ffi.sizeof(buf) then
			-- if it filled the buffer it may have truncated something, so retry
		else
			return ffi.string(buf, real_size)
		end
	end
end
local function readlinkat(dirfd, name)
	local buf = buf
	local size
	while true do
		size = ffi.C.readlinkat(dirfd, name, buf, ffi.sizeof(buf))
		if size < ffi.sizeof(buf) then
			break
		end
		buf = get_buffer(ffi.sizeof(buf) * 2)
	end
	return ffi.string(buf, size)
end
local function ensuredirat(dirfd, name, flags, mode)
	while true do
		local fd = ffi.C.openat(dirfd, name, flags, 0)
		if fd == -1 then
			local errno = ffi.errno()
			if errno == ffi.C.ENOENT then
				if ffi.C.mkdirat(dirfd, name, mode) == -1 then cerror() end
			else
				cerror()
			end
		else
			return fd
		end
	end
end

local cwd = ffi.string(ffi.gc(ffi.C.get_current_dir_name(), ffi.C.free))
local root = ffi.gc(ffi.C.fdopendir(ffi.C.openat(-100, cwd, ffi.C.O_PATH, 0)), ffi.C.closedir)
local repo = ffi.gc(ffi.C.fdopendir(ffi.C.openat(ffi.C.dirfd(root), '.fancfer', ffi.C.O_PATH, 0)), ffi.C.closedir)
local sha256_store = ffi.gc(ffi.C.fdopendir(ffi.C.openat(ffi.C.dirfd(repo), 'store/sha256', ffi.C.O_PATH, 0)), ffi.C.closedir)

local function add_blob_fd(inp)
	local tmp = ffi.C.openat(ffi.C.dirfd(repo), 'store/sha256', bit.bor(ffi.C.O_TMPFILE, ffi.C.O_RDWR), normal_file_mode)
	if tmp == -1 then cerror() end
	if ffi.C.ioctl(tmp, ffi.C.FICLONE, ffi.cast('int', inp)) == -1 then cerror() end

	local f = ffi.C.fdopen(tmp, 'r')
	local hasher = sha256()
	hasher('blob\0')
	while true do
		local len = ffi.C.fread(buf, 1, ffi.sizeof(buf), f)
		if len == 0 then break end
		hasher(buf, len)
	end
	local hash = hasher()

	if ffi.C.fsetxattr(tmp, 'user.fancfer.object-type', 'blob', 4, ffi.C.XATTR_CREATE) == -1 then cerror() end
	if ffi.C.linkat(-100, ('/proc/self/fd/%d'):format(tmp), sha256_store, hash, ffi.C.AT_SYMLINK_FOLLOW) == -1 then
		local errno = ffi.errno()
		if errno == ffi.C.EEXIST then
		else
			cerror()
		end
	end

	ffi.C.fclose(f)

	return hash
end
local function add_object_build(obj_type)
	local tmp = ffi.C.openat(ffi.C.dirfd(repo), 'store/sha256', bit.bor(ffi.C.O_TMPFILE, ffi.C.O_RDWR), normal_file_mode)
	if tmp == -1 then cerror() end

	local f = ffi.C.fdopen(tmp, 'w')
	local hasher = sha256()
	hasher(('%s\0'):format(obj_type))

	local function pump(data, len)
		if data then
			if not len then len = #data end
			hasher(data, len)
			local wr_len = ffi.C.fwrite(data, 1, len, f)
			assert(wr_len == len, 'ASSUME wr_len == len')
			return pump
		else
			local hash = hasher()

			if ffi.C.fsetxattr(tmp, 'user.fancfer.object-type', obj_type, #obj_type, ffi.C.XATTR_CREATE) == -1 then cerror() end
			if ffi.C.linkat(-100, ('/proc/self/fd/%d'):format(tmp), ffi.C.dirfd(sha256_store), hash, ffi.C.AT_SYMLINK_FOLLOW) == -1 then
				local errno = ffi.errno()
				if errno == ffi.C.EEXIST then
				else
					cerror()
				end
			end

			ffi.C.fclose(f)

			return hash
		end
	end

	return pump
end
local function add_blob_str(str)
	return add_object_build 'blob' (str) ()
end
local function add_dir(entries)
	table.sort(entries, function(a, b)
		print(a, b)
		return a[1] < b[1]
	end)
	local builder = add_object_build 'dir'
	for i = 1, #entries do
		builder(entries[i][2]) '\0'
		builder(entries[i][1]) '\0'
	end
	return builder()
end
local function add_src(src_type, arg)
	return add_object_build 'src' (src_type) '\0' (arg) '\0' ()
end

local function retrieve_object(hash)
	local fd = ffi.C.openat(ffi.C.dirfd(sha256_store), hash, ffi.C.O_RDONLY, 0)
	if fd == -1 then
		local errno = ffi.errno()
		if errno == ffi.C.ENOENT then
			return nil
		else
			cerror(errno)
		end
	end
	return ffi.gc(ffi.C.fdopen(fd, 'r'), ffi.C.fclose)
end
local function obj_type(h)
	return fgetxattr(ffi.C.fileno(h), 'user.fancfer.object-type')
end
local function retrieve_dir(h)
	if not h then return end
	do
		local ot = obj_type(h)
		if ot ~= 'dir' then
			error(('not a directory (actual type: %s)'):format(ot))
		end
	end
	local line, line_cap = ffi.new('char*[1]'), ffi.new('size_t[1]')
	line[0] = nil
	line_cap[0] = 0
	return function(_, place)
		place = place or 0
		ffi.C.fseek(h, place, ffi.C.SEEK_SET)
		local len
		len = ffi.C.getdelim(line, line_cap, 0, h)
		if len == -1 then
			ffi.C.free(line[0])
			return nil
		end
		local hash = ffi.string(line[0], len - 1)
		len = ffi.C.getdelim(line, line_cap, 0, h)
		if len == -1 then
			error 'TODO: invalid directory'
		end
		local name = ffi.string(line[0], len - 1)
		return ffi.C.ftell(h), name, hash
	end
end
local function retrieve_src(h)
	if not h then return end
	do
		local ot = obj_type(h)
		if ot ~= 'src' then
			error(('not a source (actual type: %s)'):format(ot))
		end
	end
	-- TODO: this is a terrible format
	local line, line_cap, len = ffi.new('char*[1]'), ffi.new('size_t[1]')
	line[0] = nil
	line_cap[0] = 0
	len = ffi.C.getdelim(line, line_cap, 0, h)
	assert(len ~= -1, 'ASSUME src object has type')
	local src_type = ffi.string(line[0], len - 1)
	len = ffi.C.getdelim(line, line_cap, 0, h)
	assert(len ~= -1, 'ASSUME src object has arg')
	local arg = ffi.string(line[0], len - 1)
	ffi.C.free(line[0])
	return src_type, arg
end

local flesh, src_arg, src_view, head, fake_head, list
local function flesh_real_srcs(ref, srcs_fd)
	if srcs_fd == -1 then
		local errno = ffi.errno()
		if errno == ffi.C.ENOENT then
		else
			cerror()
		end
	else
		local srcs_dir = ffi.gc(ffi.C.fdopendir(srcs_fd), ffi.C.closedir)
		local srcs_ssrcs_fd = ffi.C.openat(srcs_fd, '.fancfer-ssrcs', ffi.C.O_DIRECTORY, 0)
		local srcs_ssrcs_dir
		if srcs_ssrcs_fd == -1 then
			local errno = ffi.errno()
			if errno == ffi.C.ENOENT then
			else
				cerror()
			end
		else
			srcs_ssrcs_dir = ffi.gc(ffi.C.fdopendir(srcs_ssrcs_fd), ffi.C.closedir)
		end
		local src_names = {}
		local srcs_n = 0
		while true do
			local dirent = ffi.C.readdir(srcs_dir)
			if dirent == nil then break end
			local name = ffi.string(dirent.d_name)
			if name ~= '.' and name ~= '..' and name ~= '.fancfer-srcs' and name ~= '.fancfer-ssrcs' then
				srcs_n = srcs_n + 1
				src_names[srcs_n] = name
			end
		end
		table.sort(src_names)
		for i = srcs_n, 1, -1 do
			local name = src_names[i]
			local src_fd = ffi.C.openat(srcs_fd, name, ffi.C.O_DIRECTORY, 0)
			local src_type
			if src_fd == -1 then
				local errno = ffi.errno()
				if errno == ffi.C.ENOENT then
					if not srcs_ssrcs_dir then
						error 'TODO'
					end
					src_fd = ffi.C.openat(srcs_ssrcs_fd, name, ffi.C.O_DIRECTORY, 0)
					if src_fd == -1 then cerror() end
				else
					cerror()
				end
			end
			src_type = fgetxattr(src_fd, 'user.fancfer.source-type')
			if ffi.C.close(src_fd) == -1 then cerror() end
			ref.short.type = 'src'
			ref.short.src_type = src_type
			ref.short.src_in_dir = true
			ref.short.arg = {
				real = true;
				dir = srcs_dir;
				name = name;
				from = {
					type = 'src_arg';
					ref_short = ref.short;
				};
			}
			ref.short.val = {
				short = {
					real = true;
					dir = ref.short.dir;
					name = ref.short.name;
					from = {
						type = 'src_val';
						view = false;
						ref_short = ref.short;
					};
				};
				ext_i = ref.ext_i and ref.ext_i + 1 or nil;
				ext = ref.ext;
			}
			ref = ref.short.val
		end
	end
	return ref
end
function flesh(ref)
	if ref.short.real then
		if ref.short.type then return ref end
		local stat = ffi.new('struct statx[1]')
		if ffi.C.statx(ffi.C.dirfd(ref.short.dir), ref.short.name, ffi.C.AT_SYMLINK_NOFOLLOW, bit.bor(
			ffi.C.STATX_ALL -- TODO
		), stat) == -1 then cerror() end
		local ft = bit.band(stat[0].stx_mode, ffi.C.S_IFMT)
		local orig_ref = ref
		ref = flesh_real_srcs(ref, ffi.C.openat(ffi.C.dirfd(ref.short.dir), '.fancfer-ssrcs/' .. ref.short.name, ffi.C.O_DIRECTORY, 0))
		if ft == ffi.C.S_IFDIR then
			local fd = ffi.C.openat(ffi.C.dirfd(ref.short.dir), ref.short.name, ffi.C.O_DIRECTORY, 0)
			if fd == -1 then cerror() end
			ref = flesh_real_srcs(ref, ffi.C.openat(fd, '.fancfer-srcs', ffi.C.O_DIRECTORY, 0))
			ref.short.type = 'dir'
			ref.short.handle = ffi.gc(ffi.C.fdopendir(fd), ffi.C.closedir)
			return orig_ref
		elseif ft == ffi.C.S_IFLNK then
			local target = readlinkat(ffi.C.dirfd(ref.short.dir), ref.short.name)

			do
				local hash = target:match('^%.fancfer%-unrealized/(' .. ('[0-9a-f]'):rep(64) .. ')$')
				if hash then
					ref.short.type = 'unrealized'
					ref.short.obj = {
						real = false;
						hash = hash;
						from = {
							type = 'unrealized';
							ref_short = ref.short;
						};
					}
					return orig_ref
				end
			end
			error(('TODO: target = %q'):format(target))
		elseif ft == ffi.C.S_IFREG then
			ref.short.type = 'blob'
			return orig_ref
		else
			error(('TODO: ft == %06o'):format(ft))
		end
	else
		if not ref.short.handle then
			local h = retrieve_object(ref.short.hash)
			assert(h, 'TODO')
			ref.short.handle = h
			ref.short.type = obj_type(h)
			if ref.short.type == 'src' then
				local arg
				ref.short.src_type, arg = retrieve_src(h)
				ref.short.arg = {
					real = false;
					hash = arg;
					from = {
						type = 'src_arg';
						ref_short = ref.short;
					};
				}
			end
		end
		return ref
	end
end
function src_arg(ref)
	ref = assert(flesh(ref), 'TODO')
	if ref.short.type ~= 'src' then
		error(('not a source (actual type: %s)'):format(ref.short.type))
	end
	return {
		short = ref.short.arg;
		ext_i = ref.ext_i and ref.ext_i + 1 or nil;
		ext = ref.ext;
	}
end
function src_view(ref)
	ref = assert(flesh(ref), 'TODO')
	if ref.short.type ~= 'src' then
		error(('not a source (actual type: %s)'):format(ref.short.type))
	end
	if ref.short.src_type == 'commit_log' then
		for _, name, sub_ref in list(head(src_arg(ref))) do
			if name == 'index' then
				return fake_head {
					short = sub_ref.short;
					ext_i = 0;
					ext = {
						type = 'src_val';
						view = true;
						ref = ref;
						ref_short = ref.short;
						ext_i = sub_ref.ext_i;
						ext = sub_ref.ext;
					};
				}
			end
		end
		error 'TODO'
	else
		error(('TODO: src_type == %q'):format(ref.short.src_type))
	end
end
function src_val(ref)
	ref = assert(flesh(ref), 'TODO')
	if ref.short.type ~= 'src' then
		error(('not a source (actual type: %s)'):format(ref.short.type))
	end
	if ref.short.real then
		return ref.short.val
	else
		return src_view(ref)
	end
end
function head(ref)
	ref = assert(flesh(ref), 'TODO')
	while ref.short.type == 'src' do
		ref = src_val(ref)
		ref = assert(flesh(ref), 'TODO')
	end
	return ref
end
function fake_head(ref)
	ref = assert(flesh(ref), 'TODO')
	while ref.short.type == 'src' do
		local old_ref = ref
		ref = src_val(ref)
		ref = assert(flesh(ref), 'TODO')
		if old_ref.short.src_type == 'fake_head' then
			break
		end
	end
	return ref
end
function list(ref)
	ref = assert(flesh(ref), 'TODO')
	if ref.short.type ~= 'dir' then
		error(('not a directory (actual type: %s)'):format(ref.short.type))
	end
	if ref.short.real then
		return function(_, place)
			if place then
				ffi.C.seekdir(ref.short.handle, place)
			else
				ffi.C.rewinddir(ref.short.handle)
			end
			local dirent, name
			repeat
				dirent = ffi.C.readdir(ref.short.handle)
				if dirent == nil then return nil end
				name = ffi.string(dirent.d_name)
			until name ~= '.' and name ~= '..' and name ~= '.fancfer-srcs' and name ~= '.fancfer-ssrcs'
			return ffi.C.telldir(ref.short.handle), name, {
				short = {
					real = true;
					dir = ref.short.handle;
					name = name;
					from = {
						type = 'dir';
						name = name;
						ref_short = ref.short;
					};
				};
				ext_i = ref.ext_i and ref.ext_i + 1 or nil;
				ext = ref.ext;
			}
		end
	else
		local _next = retrieve_dir(ref.short.handle)
		return function(_, place)
			local place, name, hash = _next(_, place)
			return place, name, {
				short = {
					real = false;
					hash = hash;
					from = {
						type = 'dir';
						ref_short = ref.short;
						name = name;
					};
				};
				ext_i = ref.ext_i and ref.ext_i + 1 or nil;
				ext = ref.ext;
			}
		end
	end
end
function dir_at(ref, name_)
	for _, name, sub_ref in list(ref) do
		if name == name_ then
			return sub_ref
		end
	end
end
local function backpath(ref, pick)
	local backpath = {}
	local n = 0
	local short, ext_i, ext = ref.short, ref.ext_i, ref.ext
	while ext_i do
		while ext_i > 0 do
			n = n + 1
			backpath[n] = short.from
			short = short.from.ref_short
			ext_i = ext_i and ext_i - 1 or nil
		end
		if pick(backpath, short, ext) then
			n = n + 1
			backpath[n] = ext
			short = ext.ref.short
			ext_i = ext.ref.ext_i
			ext = ext.ref.ext
		else
			ext_i = ext.ext_i
			ext = ext.ext
		end
	end
	while short.from do
		n = n + 1
		backpath[n] = short.from
		short = short.from.ref_short
	end
	backpath.n = n
	return backpath
end
local function backpath_iter(ref, pick)
	return function(pick, st)
		if st.ext_i == 0 then
			if pick(st) then
				return st.ext.ref, st.ext
			else
				return {
					short = st.short;
					ext_i = st.ext.ext_i;
					ext = st.ext.ext;
				}, st.ext
			end
		else
			if st.short and st.short.from then
				return {
					short = st.short.from.ref_short;
					ext_i = st.ext_i and st.ext_i - 1 or nil;
					ext = st.ext;
				}, st.short.from
			else
				return nil
			end
		end
	end, pick, ref
end
local function path_str(path, step)
	local start, stop
	if step == 1 then
		start, stop, step = 1, path.n, 1
	elseif step == -1 then
		start, stop, step = path.n, 1, -1
	else
		error(('bad step, must be 1 or -1, got %q'):format(step))
	end
	local n = path.n
	local parts = {}
	local last_dir
	for i = start, stop, step do
		local j = (n + 1) * (1 - step)/2 + i * step
		if path[i].type == 'dir' then
			parts[j] = '/' .. path[i].name
			last_dir = j
		elseif path[i].type == 'src_arg' then
			local h = head { short = path[i].ref_short; }
			if h and h.short.type == 'dir' then
				parts[j] = '/.fancfer-src/TODO'
			else
				parts[j] = '/TODO'
				parts[last_dir] = '/.fancfer-ssrcs' .. parts[last_dir]
			end
		elseif path[i].type == 'src_val' then
				parts[j] = ''
		else
			error(('TODO: path[i].type == %q'):format(path[i][2].type))
		end
	end
	return table.concat(parts)
end
local realize, realize_pending_dir, realize_pending_file
function realize_find_pending(ref)
	local srcs = {}
	local srcs_n = 0
	local in_src_arg
	for up_ref, part in backpath_iter(ref, function() return true end) do
		if part.type == 'src_val' then
			srcs_n = srcs_n + 1
			srcs[srcs_n] = up_ref
		elseif part.type == 'src_arg' then
			in_src_arg = up_ref
		elseif part.type == 'dir' then
			break
		elseif part.type == 'unrealized' then
		else
			error(('TODO: part.type == %q'):format(part.type))
		end
	end
	srcs.n = srcs_n
	return srcs, in_src_arg
end
function realize_pending_dir(ref, handle, opts)
	local srcs, in_src_arg = realize_find_pending(ref)
	if srcs.n > 0 then
		if ffi.C.mkdirat(ffi.C.dirfd(handle), '.fancfer-srcs', normal_dir_mode) == -1 then cerror() end
		local srcs_fd = ffi.C.openat(ffi.C.dirfd(handle), '.fancfer-srcs', ffi.C.O_DIRECTORY, 0)
		if srcs_fd == -1 then cerror() end
		local srcs_dir = ffi.gc(ffi.C.fdopendir(srcs_fd), ffi.C.closedir)
		local digits = #tostring(srcs.n)
		for i = srcs.n, 1, -1 do
			assert(not srcs[i].short.real or srcs[i].short.src_in_dir, 'TODO')
			realize(src_arg(srcs[i]), srcs_dir, ('%%0%dd'):format(digits):format(srcs.n - i + 1), opts)
		end
	end
	if in_src_arg then
		if ffi.C.fsetxattr(ffi.C.dirfd(handle), 'user.fancfer.source-type', in_src_arg.short.src_type, #in_src_arg.short.src_type, ffi.C.XATTR_CREATE) == -1 then cerror() end
	end
end
function realize_pending_file(ref, dir, name, opts)
	local srcs, in_src_arg = realize_find_pending(ref)
	local srcs_dir
	if srcs.n > 0 or in_src_arg then
		if ffi.C.mkdirat(ffi.C.dirfd(dir), '.fancfer-ssrcs', normal_dir_mode) == -1 then
			local errno = ffi.errno()
			if errno == ffi.C.EEXIST then
			else
				cerror(errno)
			end
		end
		local ssrcs_fd = ffi.C.openat(ffi.C.dirfd(dir), '.fancfer-ssrcs', ffi.C.O_DIRECTORY, 0)
		if ssrcs_fd == -1 then cerror() end
		local ssrcs_dir = ffi.gc(ffi.C.fdopendir(ssrcs_fd), ffi.C.closedir)
		if ffi.C.mkdirat(ffi.C.dirfd(ssrcs_dir), name, normal_dir_mode) == -1 then cerror() end
		local srcs_fd = ffi.C.openat(ffi.C.dirfd(ssrcs_dir), name, ffi.C.O_DIRECTORY, 0)
		if srcs_fd == -1 then cerror() end
		srcs_dir = ffi.gc(ffi.C.fdopendir(srcs_fd), ffi.C.closedir)
	end
	if srcs.n > 0 then
		local digits = #tostring(srcs.n)
		for i = srcs.n, 1, -1 do
			assert(not srcs[i].short.real, 'TODO')
			realize(src_arg(srcs[i]), srcs_dir, ('%%0%dd'):format(digits):format(srcs.n - i + 1), opts)
		end
	end
	if in_src_arg then
		if ffi.C.fsetxattr(ffi.C.dirfd(srcs_dir), 'user.fancfer.source-type', in_src_arg.short.src_type, #in_src_arg.short.src_type, ffi.C.XATTR_CREATE) == -1 then cerror() end
	end
end
function realize(ref, dir, name, opts)
	ref = assert(flesh(ref), 'TODO')
	assert(not ref.real, 'TODO')
	if not opts.filter(ref, dir, name) then
		realize_pending_file(ref, dir, name, opts)
		if ffi.C.symlinkat('.fancfer-unrealized/' .. ref.short.hash, ffi.C.dirfd(dir), name) == -1 then cerror() end
	elseif ref.short.type == 'src' then
		realize(src_val(ref), dir, name, opts)
	elseif ref.short.type == 'dir' then
		if ffi.C.mkdirat(ffi.C.dirfd(dir), name, normal_dir_mode) == -1 then cerror() end
		local fd = ffi.C.openat(ffi.C.dirfd(dir), name, ffi.C.O_DIRECTORY, 0)
		if fd == -1 then cerror() end
		local handle = ffi.gc(ffi.C.fdopendir(fd), ffi.C.closedir)
		realize_pending_dir(ref, handle, opts)
		for _, name, sub_ref in list(ref) do
			realize(sub_ref, handle, name, opts)
		end
	elseif ref.short.type == 'blob' then
		realize_pending_file(ref, dir, name, opts)
		local fd = ffi.C.openat(ffi.C.dirfd(dir), name, bit.bor(ffi.C.O_CREAT, ffi.C.O_WRONLY), normal_file_mode)
		if fd == -1 then cerror() end
		if ffi.C.ioctl(fd, ffi.C.FICLONE, ffi.cast('int', ffi.C.fileno(ref.short.handle))) == -1 then cerror() end
		if ffi.C.close(fd) == -1 then cerror() end
	elseif ref.short.type == 'unrealized' then
		if ffi.C.unlinkat(ffi.C.dirfd(dir), name, 0) == -1 then cerror() end
		realize({
			short = ref.short.obj;
			ext_i = ref.ext_i and ref.ext_i + 1 or nil;
			ext = ref.ext;
		}, dir, name, opts)
	else
		error(('TODO: ref.short.type == %q'):format(ref.short.type))
	end
end
local function ref_str(ref)
	local parts = {}
	local parts_n = 0
	for up_ref, part in backpath_iter(ref, function() return true end) do
		parts_n = parts_n + 1
		local part_str
		if part.type == 'src_arg' or part.type == 'src_val' then
			part_str = part.type
		elseif part.type == 'dir' then
			part_str = 'dir:' .. part.name
		elseif part.type == 'real_root' then
			part_str = ('real_root(%s, %s)'):format(
				readlinkat(-100, ('/proc/self/fd/%d'):format(ffi.C.dirfd(part.dir))),
				part.name
			)
		else
			error(('TODO: part.type == %q'):format(part.type))
		end
		parts[parts_n] = part_str
	end
	for i = 1, math.floor(parts_n/2) do
		parts[i], parts[parts_n - i + 1] = parts[parts_n - i + 1], parts[i]
	end
	return table.concat(parts, '/')
end

local function copy(src, dst, opts)
	src = assert(flesh(src), 'TODO')
	print(ref_str(src))
end

local test_obj = add_src('commit_log', add_dir {
	{'index', add_dir {
		{'foo', add_blob_str 'foo1'};
	}};
})
-- local test_obj = add_dir {
-- 	{'wat', add_src('commit_log', add_dir {
-- 		{'index', add_blob_str 'foo1'};
-- 	})};
-- }

local test_ref = { short = {
	real = false;
	hash = test_obj;
	from = {
		type = 'virtual_root';
		hash = test_obj;
	};
}; }

-- realize(test_ref, root, 'test1', {
-- 	filter = function(ref, dir, name)
-- 		return true
-- 		-- return not (ref.short.from and ref.short.from.type == 'src_arg')
-- 	end;
-- })

local root_ref = flesh { short = {
	real = true;
	dir = root;
	name = 'test1';
	from = {
		type = 'real_root';
		dir = root;
		name = 'test1';
	};
}; }

copy(head(root_ref), {
	type = 'real_root';
	dir = root;
	name = 'test2';
}, {
	filter = function(src, dst)
		print(src, dst)
		return true
	end;
})
