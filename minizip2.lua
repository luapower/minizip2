
--Minizip 2 binding.
--Written by Cosmin Apreutesei. Public Domain.

local ffi = require'ffi'
require'minizip2_h'
require'minizip2_rw_h'
local C = ffi.load'minizip2'
local M = {C = C}

--MZ_ERROR
local MZ_OK                           = 0  --zlib
local MZ_STREAM_ERROR                 = -1 --zlib
local MZ_DATA_ERROR                   = -3 --zlib
local MZ_MEM_ERROR                    = -4 --zlib
local MZ_BUF_ERROR                    = -5 --zlib
local MZ_VERSION_ERROR                = -6 --zlib

local MZ_END_OF_LIST                  = -100
local MZ_END_OF_STREAM                = -101

local MZ_PARAM_ERROR                  = -102
local MZ_FORMAT_ERROR                 = -103
local MZ_INTERNAL_ERROR               = -104
local MZ_CRC_ERROR                    = -105
local MZ_CRYPT_ERROR                  = -106
local MZ_EXIST_ERROR                  = -107
local MZ_PASSWORD_ERROR               = -108
local MZ_SUPPORT_ERROR                = -109
local MZ_HASH_ERROR                   = -110
local MZ_OPEN_ERROR                   = -111
local MZ_CLOSE_ERROR                  = -112
local MZ_SEEK_ERROR                   = -113
local MZ_TELL_ERROR                   = -114
local MZ_READ_ERROR                   = -115
local MZ_WRITE_ERROR                  = -116
local MZ_SIGN_ERROR                   = -117
local MZ_SYMLINK_ERROR                = -118

--MZ_OPEN
local MZ_OPEN_MODE_READ               = 0x01
local MZ_OPEN_MODE_WRITE              = 0x02
local MZ_OPEN_MODE_READWRITE          = MZ_OPEN_MODE_READ + MZ_OPEN_MODE_WRITE
local MZ_OPEN_MODE_APPEND             = 0x04
local MZ_OPEN_MODE_CREATE             = 0x08
local MZ_OPEN_MODE_EXISTING           = 0x10

--MZ_SEEK
local MZ_SEEK_SET                     = 0
local MZ_SEEK_CUR                     = 1
local MZ_SEEK_END                     = 2

--MZ_COMPRESS
local MZ_COMPRESS_METHOD_STORE        = 0
local MZ_COMPRESS_METHOD_DEFLATE      = 8
local MZ_COMPRESS_METHOD_BZIP2        = 12
local MZ_COMPRESS_METHOD_LZMA         = 14
local MZ_COMPRESS_METHOD_AES          = 99

local MZ_COMPRESS_LEVEL_DEFAULT       = -1
local MZ_COMPRESS_LEVEL_FAST          = 2
local MZ_COMPRESS_LEVEL_NORMAL        = 6
local MZ_COMPRESS_LEVEL_BEST          = 9

--MZ_ZIP_FLAG
local MZ_ZIP_FLAG_ENCRYPTED           = 2^0
local MZ_ZIP_FLAG_LZMA_EOS_MARKER     = 2^1
local MZ_ZIP_FLAG_DEFLATE_MAX         = 2^1
local MZ_ZIP_FLAG_DEFLATE_NORMAL      = 0
local MZ_ZIP_FLAG_DEFLATE_FAST        = 2^2
local MZ_ZIP_FLAG_DEFLATE_SUPER_FAST  = MZ_ZIP_FLAG_DEFLATE_FAST + MZ_ZIP_FLAG_DEFLATE_MAX
local MZ_ZIP_FLAG_DATA_DESCRIPTOR     = 2^3
local MZ_ZIP_FLAG_UTF8                = 2^11
local MZ_ZIP_FLAG_MASK_LOCAL_INFO     = 2^13

-- MZ_ZIP_EXTENSION
local MZ_ZIP_EXTENSION_ZIP64          = 0x0001
local MZ_ZIP_EXTENSION_NTFS           = 0x000a
local MZ_ZIP_EXTENSION_AES            = 0x9901
local MZ_ZIP_EXTENSION_UNIX1          = 0x000d
local MZ_ZIP_EXTENSION_SIGN           = 0x10c5
local MZ_ZIP_EXTENSION_HASH           = 0x1a51
local MZ_ZIP_EXTENSION_CDCD           = 0xcdcd

-- MZ_ZIP64
local MZ_ZIP64_AUTO                   = 0
local MZ_ZIP64_FORCE                  = 1
local MZ_ZIP64_DISABLE                = 2

-- MZ_HOST_SYSTEM
local MZ_HOST_SYSTEM_MSDOS            = 0
local MZ_HOST_SYSTEM_UNIX             = 3
local MZ_HOST_SYSTEM_WINDOWS_NTFS     = 10
local MZ_HOST_SYSTEM_RISCOS           = 13
local MZ_HOST_SYSTEM_OSX_DARWIN       = 19

-- MZ_PKCRYPT
local MZ_PKCRYPT_HEADER_SIZE          = 12

-- MZ_AES
local MZ_AES_VERSION                  = 1
local MZ_AES_ENCRYPTION_MODE_128      = 0x01
local MZ_AES_ENCRYPTION_MODE_192      = 0x02
local MZ_AES_ENCRYPTION_MODE_256      = 0x03
local MZ_AES_KEY_LENGTH_MAX           = 32
local MZ_AES_BLOCK_SIZE               = 16
local MZ_AES_FOOTER_SIZE              = 10

-- MZ_HASH
local MZ_HASH_MD5                     = 10
local MZ_HASH_MD5_SIZE                = 16
local MZ_HASH_SHA1                    = 20
local MZ_HASH_SHA1_SIZE               = 20
local MZ_HASH_SHA256                  = 23
local MZ_HASH_SHA256_SIZE             = 32
local MZ_HASH_MAX_SIZE                = 256

-- MZ_ENCODING
local MZ_ENCODING_CODEPAGE_437        = 437
local MZ_ENCODING_CODEPAGE_932        = 932
local MZ_ENCODING_CODEPAGE_936        = 936
local MZ_ENCODING_CODEPAGE_950        = 950
local MZ_ENCODING_UTF8                = 65001

ffi.cdef[[
typedef struct minizip_reader_t;
typedef struct minizip_writer_t;
]]

local reader = {}
local writer = {}

local rbuf = ffi.new'struct minizip_reader_t*[1]'
local wbuf = ffi.new'struct minizip_writer_t*[1]'
local ebuf = ffi.new'mz_zip_entry'
local pebuf = ffi.new'mz_zip_entry*[1]'

local get_entry = {}

function get_entry:filename   () return str(self._filename, self.filename_size) end
function get_entry:extrafield () return str(self._extrafield, self.extrafield_size) end
function get_entry:comment    () return str(self._comment, self.comment_size) end
function get_entry:linkname   () return str(self._linkname) end

local function str(s, len)
	return s ~= nil and ffi.string(s, len) or nil
end

ffi.metatype('mz_zip_entry', {__index = function(self, k)
	local getter = get_entry[k]
	if getter then return getter(self) end
	error(string.format('unknown entry field %s', k))
end})

local function setebuf(t)
	return ebuf
end

local function check(err, ret)
	if err ~= MZ_OK then return nil, err end
	return ret or true
end

local function checklen(err)
	if err < 0 then return nil, err end
	return err > 0 and err or nil
end

local function open_reader(t)
	C.mz_zip_reader_create(rbuf)
	local z = rbuf[0]
	local err
	if t.file then
		err = C.mz_zip_reader_open_file(z, t.file)
	elseif t.data then
		err = C.mz_zip_reader_open_buffer(z, t.data, t.len or #t.data, false)
		ffi.gc(z, function() local _ = t.data end) --anchor it
	else
		--TODO: int32_t mz_zip_reader_open(void *handle, void *stream);
		assert(false)
	end
	if err ~= MZ_OK then
 		C.mz_zip_reader_delete(rbuf)
		return nil, err
	else
		return true
	end
end

local function open_writer(t)
	C.mz_zip_writer_create(wbuf)
	local z = wbuf[0]

	if t.password then
		C.mz_zip_writer_set_password(z, t.password)
	end
	if t.compress_method then
		C.mz_zip_writer_set_compress_method(z, t.compress_method)
	end
	if t.compress_level then
		C.mz_zip_writer_set_compress_level(z, t.compress_level)
	end
	if t.follow_links then
		C.mz_zip_writer_set_follow_links(z, t.follow_links)
	end
	if t.store_links then
		C.mz_zip_writer_set_store_links(z, t.store_links)
	end
	if t.zip_cd then
		C.mz_zip_writer_set_zip_cd(z, t.zip_cd)
	end
	if t.cert_path then
		C.mz_zip_writer_set_certificate(z, t.cert_path, t.cert_pwd)
	end

	local err
	if t.file then
		err = C.mz_zip_writer_open_file(z, t.file, t.disk_size or 0, t.mode == 'a')
	else
		--TODO: int32_t mz_zip_writer_open(void *handle, void *stream);
		assert(false)
	end

	if err ~= MZ_OK then
		C.mz_zip_writer_delete(wbuf)
		return nil, err
	else
		return true
	end
end

function M.open(t)
	local open = (t.mode or 'r') == 'r' and open_reader or open_writer
	return open(t)
end

function reader:close()
	C.mz_zip_reader_close(self)
	rbuf[0] = self
	C.mz_zip_reader_delete(rbuf)
end

function writer:close()
	C.mz_zip_writer_close(self)
	wbuf[0] = self
	C.mz_zip_writer_delete(wbuf)
end

local function checkeol(err)
	if err ~= MZ_OK then return nil, err end
	if err == MZ_END_OF_LIST then return nil end
	return true
end

function reader:first()
	return checkeol(C.mz_zip_reader_goto_first_entry(self))
end

function reader:next()
	return checkeol(C.mz_zip_reader_goto_next_entry(self))
end

function reader:find(filename, ignore_case)
	return check(C.mz_zip_reader_locate_entry(self, filename, ignore_case))
end

function reader:info()
	local ok, err = check(C.mz_zip_reader_entry_get_info(self, pebuf))
	if not ok then return nil, err end
	return pebuf[0]
end

function reader:files()
	return function(e)
		if e == false then return nil end
		if not e then
			local ok, err = self:first()
			if not ok then return false, err end
		else
			local ok, err = self:next()
			if not ok then return false, err end
		end
		local e, err = self:info()
		if not e then return false, err end
		return e
	end
end

function reader:is_dir()
	return check(C.mz_zip_reader_entry_is_dir(self))
end

function reader:open_entry()
	return check(C.mz_zip_reader_entry_open(self))
end

function reader:read(buf, len)
	if buf == '*a' then
		local len = C.mz_zip_reader_entry_save_buffer_length(self)
		local buf = ffi.new('char[?]', len)
		local ok, err = check(C.mz_zip_reader_entry_save_buffer(self, buf, len))
		if not ok then return nil, err end
		return str(buf, len)
	else
		return checklen(C.mz_zip_reader_entry_read(self, buf, len))
	end
end

function reader:close_entry()
	return check(C.mz_zip_reader_entry_close(self))
end

function reader:extract(dest_file)
	return check(C.mz_zip_reader_entry_save_file(self, dest_file))
end

function reader:extract_all(dest_dir)
	return check(C.mz_zip_reader_save_all(self, dest_dir))
end

function writer:add_entry(entry)
	return check(C.mz_zip_writer_add_info(self, nil, nil, setebuf(entry)))
end

function writer:write(buf, len)
	return checklen(C.mz_zip_writer_entry_write(self, buf, len or #buf))
end

function writer:close_entry()
	return check(C.mz_zip_writer_entry_close(self))
end

function writer:add_file(file, filename_in_zip)
	return check(C.mz_zip_writer_add_file(self, file, filename_in_zip))
end

function writer:add_memfile(entry)
	return check(C.mz_zip_writer_add_buffer(self,
		entry.data, entry.len or #entry.data, setebuf(entry)))
end

function writer:add_dir(dir, root_dir, include_path, recursive)
	return check(C.mz_zip_writer_add_path(self, dir, root_dir,
		include_path or false,
		recursive ~= false))
end

function writer:add_all_from_zip(reader)
	return check(C.mz_zip_writer_copy_from_reader(self, reader))
end

ffi.metatype('struct minizip_reader_t', {__index = reader})
ffi.metatype('struct minizip_writer_t', {__index = writer})

