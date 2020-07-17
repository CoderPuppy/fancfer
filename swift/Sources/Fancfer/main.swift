import Crypto
import Glibc
import FancferC
import Foundation

extension Sequence {
	@inlinable
	func withUnsafeBufferPointer<R>(
		_ body: (UnsafeBufferPointer<Element>) throws -> R
	) rethrows -> R {
		if let ret = try withContiguousStorageIfAvailable(body) {
			return ret
		} else {
			return try ContiguousArray(self).withUnsafeBufferPointer(body)
		}
	}
}

extension HashFunction {
	@inlinable
	mutating func update<S: Sequence>(sequence: S) {
		sequence.withUnsafeBufferPointer { (ptr) in
			self.update(bufferPointer: UnsafeRawBufferPointer(ptr))
		}
	}
}

struct CError: Error {
	let errno: CInt

	init(errno: CInt) {
		self.errno = errno
	}

	init() {
		self.init(errno: Glibc.errno)
	}
}

struct FSRef {
	let dir: Directory?
	let path: String

	func _open(flags: CInt, mode: Glibc.mode_t) throws -> CInt {
		let fd = path.withCString { (ptr) in
			Glibc.openat(dir?.fd ?? AT_FDCWD, ptr, flags, mode)
		}
		guard fd != -1 else {
			throw CError(errno: Glibc.errno)
		}
		return fd
	}

	func openDirectory() throws -> Directory {
		return try Directory(ref: self)
	}
}

let normalFileMode = Glibc.S_IROTH | Glibc.S_IRGRP | Glibc.S_IRUSR | Glibc.S_IWUSR
let normalDirMode = Glibc.S_IXOTH | Glibc.S_IROTH | Glibc.S_IXGRP | Glibc.S_IRGRP | Glibc.S_IXUSR | Glibc.S_IRUSR | Glibc.S_IWUSR

class Directory {
	var ptr: OpaquePointer

	init(ptr: OpaquePointer) {
		self.ptr = ptr
	}

	convenience init(ref: FSRef) throws {
		let fd = try ref._open(flags: Glibc.O_DIRECTORY, mode: 0)
		let ptr = Glibc.fdopendir(fd)!
		self.init(ptr: ptr)
	}

	var fd: CInt { get { dirfd(ptr) } }

	static func / (dir: Directory, path: String) -> FSRef {
		FSRef(dir: dir, path: path)
	}

	func makeTempFile(mode: Glibc.mode_t = normalFileMode) throws -> File {
		let fd = Glibc.openat(dirfd(ptr), ".", O_TMPFILE | O_RDWR, mode)
		guard fd != -1 else {
			throw CError(errno: Glibc.errno)
		}
		let ptr = Glibc.fdopen(fd, "w+")!
		return File(ptr: ptr)
	}
}

class File: TextOutputStream {
	var ptr: UnsafeMutablePointer<Glibc.FILE>

	init(ptr: UnsafeMutablePointer<Glibc.FILE>) {
		self.ptr = ptr
	}

	deinit {
		fclose(self.ptr)
	}

	var fd: CInt { get { fileno(ptr) } }

	func write(_ ptr: UnsafeBufferPointer<UInt8>) throws {
		guard Glibc.fwrite(ptr.baseAddress!, ptr.count, 1, self.ptr) != -1 else {
			throw CError(errno: Glibc.errno)
		}
	}

	func write(_ string: String) {
		do {
			try string.utf8.withUnsafeBufferPointer { (ptr) in
				try self.write(ptr)
			}
		} catch {
			// TODO: TextOutputStream does not allow this to throw
		}
	}

	func currentPos() throws -> Int {
		let pos = Glibc.ftell(self.ptr)
		guard pos != -1 else {
			throw CError(errno: Glibc.errno)
		}
		return pos
	}

	func seekTo(startPlus count: Int) throws {
		guard Glibc.fseek(self.ptr, count, Glibc.SEEK_SET) != -1 else {
			throw CError(errno: Glibc.errno)
		}
	}

	func readAll(initialSize: Int = 1024) throws -> UnsafeMutableBufferPointer<Int8> {
		var buffer = Glibc.malloc(initialSize)!
		var nread = 0
		var remaining = initialSize
		while Glibc.feof(self.ptr) == 0 {
			if remaining == 0 {
				buffer = Glibc.realloc(buffer, nread * 2)!
				remaining += nread
			}
			let len = Glibc.fread(buffer + nread, 1, remaining, self.ptr)
			guard Glibc.ferror(self.ptr) == 0 else {
				// TODO: I'm not sure about this
				throw CError(errno: Glibc.errno)
			}
			nread += len
			remaining -= len
		}
		return UnsafeMutableRawBufferPointer(start: buffer, count: nread).bindMemory(to: Int8.self)
	}
}

extension File {
	class Getdelim {
		var line: UnsafeMutablePointer<Int8>? = nil
		var lineCap: Int = 0

		deinit {
			if line != nil {
				Glibc.free(line)
			}
		}

		func read(from file: File, delimitedBy delimiter: CChar) throws -> String? {
			Glibc.errno = 0
			let len = withUnsafeMutablePointer(to: &self.line) { (line_ptr) in
				Glibc.getdelim(line_ptr, &self.lineCap, Int32(delimiter), file.ptr)
			}
			guard len != -1 else {
				let err = Glibc.errno
				// TODO: this is terrible, but I don't know a better way
				if err == 0 {
					return nil
				} else {
					throw CError(errno: err)
				}
			}
			return String(cString: line!)
		}
	}
}

extension Digest {
	func hexString() -> String {
		return Array(self).map { String(format: "%02x", $0) }.joined()
	}
}

struct InvalidObject: Error {
}

struct Store<H: HashFunction> {
	var dir: Directory
	var hf: H.Type

	struct Object {
		let hash: String
		let type: String
		var file: File

		internal init(hash: String, file: File) throws {
			self.hash = hash
			self.file = file
			self.type = try "user.fancfer.object-type".withCString { (key_ptr) in
				let expectedSize = FancferC.fgetxattr(file.fd, key_ptr, nil, 0)
				guard expectedSize != -1 else {
					throw CError(errno: Glibc.errno)
				}
				return try String(unsafeUninitializedCapacity: Int(expectedSize), initializingUTF8With: { (buffer) in
					let realSize = FancferC.fgetxattr(file.fd, key_ptr, UnsafeMutableRawPointer(buffer.baseAddress!), buffer.count)
					guard realSize != -1 else {
						throw CError(errno: Glibc.errno)
					}
					return Int(realSize)
				})
			}
		}

		func contents() throws -> String {
			try self.file.seekTo(startPlus: 0)
			let buffer = try self.file.readAll()
			defer { Glibc.free(buffer.baseAddress!) }
			return String(cString: buffer.baseAddress!)
		}

		func dir() throws -> Dictionary<String, String> {
			guard self.type == "dir" else { throw InvalidObject() }
			try self.file.seekTo(startPlus: 0)
			let getdelim = File.Getdelim()
			var dict = Dictionary<String, String>()
			while let hash = try getdelim.read(from: self.file, delimitedBy: 0) {
				guard let name = try getdelim.read(from: self.file, delimitedBy: 0) else {
					throw InvalidObject()
				}
				dict[name] = hash
			}
			return dict
		}

		func blob() throws -> String {
			guard self.type == "blob" else { throw InvalidObject() }
			return try self.contents()
		}

		func src() throws -> (String, String) {
			guard self.type == "src" else { throw InvalidObject() }
			try self.file.seekTo(startPlus: 0)
			let getdelim = File.Getdelim()
			guard let type = try getdelim.read(from: self.file, delimitedBy: 0) else {
				throw InvalidObject()
			}
			guard let arg = try getdelim.read(from: self.file, delimitedBy: 0) else {
				throw InvalidObject()
			}
			return (type, arg)
		}
	}

	func lookup(hash: String) throws -> Object? {
		let fd = try (dir/hash)._open(flags: Glibc.O_RDONLY, mode: 0)
		let file = File(ptr: Glibc.fdopen(fd, "r"))
		return try Object(hash: hash, file: file)
	}

	func insertBlob(file: File) throws -> String {
		let f = try dir.makeTempFile()
		guard ioctl_ficlone(f.fd, file.fd) != -1 else {
			throw CError(errno: Glibc.errno)
		}
		var hasher = hf.init()
		hasher.update(sequence: "blob\0".utf8)
		let hash = hasher.finalize()
		try "user.fancfer.object-type".withCString { (key_ptr) in
			try "blob".utf8.withUnsafeBufferPointer { (val_ptr) in
				guard FancferC.fsetxattr(f.fd, key_ptr, val_ptr.baseAddress!, val_ptr.count, XATTR_CREATE) != -1 else {
					throw CError(errno: Glibc.errno)
				}
			}
		}
		try "/proc/self/fd/\(f.fd)".withCString { (src_ptr) in
			try hash.hexString().withCString { (dst_ptr) in
				if linkat(AT_FDCWD, src_ptr, dir.fd, dst_ptr, AT_SYMLINK_FOLLOW) == -1 {
					let err = Glibc.errno
					if err == EEXIST {
					} else {
						throw CError(errno: err)
					}
				}
			}
		}
		return hash.hexString()
	}

	func build(type: String) throws -> BuildingObject<H> {
		try BuildingObject(store: self, type: type)
	}

	class BuildingObject<H: HashFunction>: TextOutputStream {
		let store: Store<H>
		let type: String
		var file: File
		var hasher: H

		init(store: Store<H>, type: String) throws {
			self.store = store
			self.type = type
			self.file = try self.store.dir.makeTempFile()
			self.hasher = store.hf.init()

			try "user.fancfer.object-type".withCString { (key_ptr) in
				try type.utf8.withUnsafeBufferPointer { (val_ptr) in
					guard FancferC.fsetxattr(self.file.fd, key_ptr, val_ptr.baseAddress!, val_ptr.count, XATTR_CREATE) != -1 else {
						throw CError(errno: Glibc.errno)
					}
				}
			}
		
			self.hasher.update(sequence: self.type.utf8)
			self.hasher.update(data: [0])
		}

		func write(_ string: String) {
			self.file.write(string)
			self.hasher.update(sequence: string.utf8)
		}

		func finalize() throws -> String {
			let hash = self.hasher.finalize().hexString()
			try "/proc/self/fd/\(self.file.fd)".withCString { (src_ptr) in
				try hash.withCString { (dst_ptr) in
					if linkat(AT_FDCWD, src_ptr, self.store.dir.fd, dst_ptr, AT_SYMLINK_FOLLOW) == -1 {
						let err = Glibc.errno
						if err == EEXIST {
						} else {
							throw CError(errno: err)
						}
					}
				}
			}
			return hash
		}
	}

	func insertBlob(str: String) throws -> String {
		let builder = try build(type: "blob")
		builder.write(str)
		return try builder.finalize()
	}

	func insertDir(dict: Dictionary<String, String>) throws -> String {
		let builder = try build(type: "dir")
		for (name, hash) in dict {
			builder.write(hash + "\0" + name + "\0")
		}
		return try builder.finalize()
	}

	func insertSrc(type: String, arg: String) throws -> String {
		let builder = try build(type: "src")
		builder.write(type + "\0")
		builder.write(arg + "\0")
		return try builder.finalize()
	}
}

let root = try Directory(ref: FSRef(dir: nil, path: "../test-repo"))
let s = Store(dir: try Directory(ref: root/".fancfer/store/sha256"), hf: SHA256.self)
let buz = try s.insertBlob(str: "buz")
print("buz", buz)
let baz = try s.insertBlob(str: "baz")
print("baz", baz)
let dir = try s.insertDir(dict: ["fiz": buz, "bar": baz])
print("dir", dir)

try print(s.lookup(hash: dir)!.dir())
