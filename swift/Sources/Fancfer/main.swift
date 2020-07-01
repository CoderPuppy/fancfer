import Crypto
// import Glibc
import FancferC

struct CError: Error {
	let errno: CInt
}

struct FSRef {
	let dir: Directory?
	let path: String

	func _open(flags: CInt, mode: CInt) throws -> CInt {
		let fd = path.utf8CString.withUnsafeBufferPointer { (ptr) in
			openat(dir?.fd ?? AT_FDCWD, ptr.baseAddress!, flags, mode)
		}
		guard fd != -1 else {
			throw CError(errno: errno)
		}
		return fd
	}

	func openDirectory() throws -> Directory {
		return try Directory(ref: self)
	}
}

let normalFileMode = S_IROTH | S_IRGRP | S_IRUSR | S_IWUSR
let normalDirMode = S_IXOTH | S_IROTH | S_IXGRP | S_IRGRP | S_IXUSR | S_IRUSR | S_IWUSR

class Directory {
	var ptr: OpaquePointer

	init(ptr: OpaquePointer) {
		self.ptr = ptr
	}

	convenience init(ref: FSRef) throws {
		let fd = try ref._open(flags: O_DIRECTORY, mode: 0)
		let ptr = fdopendir(fd)!
		self.init(ptr: ptr)
	}

	var fd: CInt { get { dirfd(ptr) } }

	static func / (dir: Directory, path: String) -> FSRef {
		FSRef(dir: dir, path: path)
	}

	func makeTempFile(mode: CInt = normalFileMode) throws -> File {
		let fd = openat(dirfd(ptr), ".", O_TMPFILE | O_RDWR, normalFileMode)
		guard fd != -1 else {
			throw CError(errno: errno)
		}
		let ptr = fdopen(fd, "w+")!
		return File(ptr: ptr)
	}
}

class File {
	var ptr: OpaquePointer

	init(ptr: OpaquePointer) {
		self.ptr = ptr
	}

	var fd: CInt { get { fileno(ptr) } }
}

struct Store<H: HashFunction> {
	var dir: Directory
	var hf: H.Type

	func ref(_ hash: H.Digest) -> FSRef {
		FSRef(dir: dir, path: Array(hash).map { String(format: "%02x", $0) }.joined())
	}

	func insert(file: File) throws -> H.Digest {
		let f = try dir.makeTempFile()
		guard ioctl_ficlone(f.fd, file.fd) != -1 else {
			throw CError(errno: errno)
		}
		var hasher = hf.init()
		hasher.update(data: Array("blob\0".utf8))
		let hash = hasher.finalize()
		try "user.fancfer.object-type".utf8CString.withUnsafeBufferPointer { (key_ptr) in
			try Array("blob".utf8).withUnsafeBufferPointer { (val_ptr) in
				guard fsetxattr(f.fd, key_ptr.baseAddress!, val_ptr.baseAddress!, val_ptr.count, XATTR_CREATE) != -1 else {
					throw CError(errno: errno)
				}
			}
		}
		try "/proc/self/fd/${f.fd}".utf8CString.withUnsafeBufferPointer { (src_ptr) in
			try ref(hash).path.utf8CString.withUnsafeBufferPointer { (dst_ptr) in
				guard linkat(AT_FDCWD, src_ptr.baseAddress!, dir.fd, dst_ptr.baseAddress!, AT_SYMLINK_FOLLOW) != -1 else {
					throw CError(errno: errno)
				}
			}
		}
		return hash
	}
}

let root = try Directory(ref: FSRef(dir: nil, path: "../test-repo"))
let s = Store(dir: try Directory(ref: root/".fancfer/store/sha256"), hf: SHA256.self)
let hf = SHA256()
let digest = hf.finalize()
print(s.ref(digest))
