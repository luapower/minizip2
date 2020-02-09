
--Minizip 2 ffi binding.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'minizip2_test'; return end

local ffi = require'ffi'
require'minizip2_h'
require'minizip2_rw_h'
local C = ffi.load'minizip2'
local M = {C = C}

--tools ----------------------------------------------------------------------

local glue = {}

--reverse keys with values.
function glue.index(t)
	local dt={}
	for k,v in pairs(t) do dt[v]=k end
	return dt
end

--return a metatable that supports virtual properties.
function glue.gettersandsetters(t, getters, setters, super)
	local get = getters and function(t, k)
		local get = getters[k]
		if get then return get(t) end
		return super[k]
	end
	local set = setters and function(t, k, v)
		local set = setters[k]
		if set then set(t, v); return end
		rawset(t, k, v)
	end
	return {__index = get, __newindex = set}
end

local function str(s, len)
	return s ~= nil and ffi.string(s, len) or nil
end

--zip entry ------------------------------------------------------------------

local entry_get = {}

function entry_get:filename   () return str(self.filename_ptr, self.filename_size) end
function entry_get:extrafield () return str(self.extrafield_ptr, self.extrafield_size) end
function entry_get:comment    () return str(self.comment_ptr, self.comment_size) end
function entry_get:linkname   () return str(self.linkname_ptr) end

local compression_methods = {
	store   = C.MZ_COMPRESS_METHOD_STORE  ,
	deflate = C.MZ_COMPRESS_METHOD_DEFLATE,
	bzip2   = C.MZ_COMPRESS_METHOD_BZIP2  ,
	lzma    = C.MZ_COMPRESS_METHOD_LZMA   ,
	aes     = C.MZ_COMPRESS_METHOD_AES    ,
}
local compression_method_names = glue.index(compression_methods)

function entry_get:compression_method()
	return compression_method_names[self.compression_method_num]
end

local encryption_modes = {
	[C.MZ_AES_ENCRYPTION_MODE_128] = 128,
	[C.MZ_AES_ENCRYPTION_MODE_192] = 192,
	[C.MZ_AES_ENCRYPTION_MODE_256] = 256,
}
function entry_get:aes_bits()
	return aes_bits[self.aes_encryption_mode]
end

function entry_get:compressed_size() return tonumber(self.compressed_size_i64) end
function entry_get:uncompressed_size() return tonumber(self.uncompressed_size_i64) end
function entry_get:disk_offset() return tonumber(self.disk_offset_i64) end
function entry_get:zip64() return self.zip64_u16 == 1 end

ffi.metatype('mz_zip_entry', glue.gettersandsetters(entry_get))

--reader & writer ------------------------------------------------------------

ffi.cdef[[
typedef struct minizip_reader_t;
typedef struct minizip_writer_t;
]]

local reader = {}; local reader_get = {}; local reader_set = {}
local writer = {}; local writer_get = {}; local writer_set = {}

local rbuf = ffi.new'struct minizip_reader_t*[1]'
local wbuf = ffi.new'struct minizip_writer_t*[1]'
local ebuf = ffi.new'mz_zip_entry'
local pebuf = ffi.new'mz_zip_entry*[1]'

local function setebuf(t)
	return ebuf --TODO: read t
end

local function check(err, ret)
	if err < 0 then return nil, err end
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
		if t.in_memory then
			err = C.mz_zip_reader_open_file_in_memory(z, t.file)
		else
			err = C.mz_zip_reader_open_file(z, t.file)
		end
	elseif t.data then
		err = C.mz_zip_reader_open_buffer(z, t.data, t.len or #t.data, t.copy or false)
		ffi.gc(z, function() local _ = t.data end) --anchor it
	else
		--TODO: int32_t mz_zip_reader_open(void *handle, void *stream);
		assert(false)
	end
	if err ~= 0 then
 		C.mz_zip_reader_delete(rbuf)
		return nil, err
	else
		return true
	end
end

local function open_writer(t)
	C.mz_zip_writer_create(wbuf)
	local z = wbuf[0]

	--TODO: use t to set z

	local err
	if t.file then
		err = C.mz_zip_writer_open_file(z, t.file, t.disk_size or 0, t.mode == 'a')
	else
		--TODO: int32_t mz_zip_writer_open(void *handle, void *stream);
		assert(false)
	end

	if err ~= 0 then
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

--reader entry catalog

local function checkeol(err)
	if err < 0 then return nil, err end
	return err ~= C.MZ_END_OF_LIST
end

function reader:first()
	return checkeol(C.mz_zip_reader_goto_first_entry(self))
end

function reader:next()
	return checkeol(C.mz_zip_reader_goto_next_entry(self))
end

function reader:find(filename, ignore_case)
	return check(C.mz_zip_reader_locate_entry(self, filename, ignore_case or false))
end

function reader_get:entry()
	assert(check(C.mz_zip_reader_entry_get_info(self, pebuf)))
	return pebuf[0]
end

function reader:entries()
	return function(e)
		if e == false then return nil end
		if not e then
			local ok, err = self:first()
			if not ok then return false, err end
		else
			local ok, err = self:next()
			if not ok then return false, err end
		end
		local e, err = self:entry()
		if not e then return false, err end
		return e
	end
end

function reader_set:pattern(pattern)
	C.mz_zip_reader_set_pattern(self, pattern, false)
end

function reader_set:ci_pattern(pattern)
	C.mz_zip_reader_set_pattern(self, pattern, true)
end

function reader_set:encoding(encoding)
	if encoding == 'utf8' then encoding = C.MZ_ENCODING_UTF8 end
	C.mz_zip_reader_set_encoding(self, encoding)
end

local cbuf = ffi.new'char*[1]'
function reader_get:comment()
	assert(check(C.mz_zip_reader_get_comment(self, cbuf)))
	return str(cbuf)
end

function reader_get:zip_cd()
	assert(check(C.mz_zip_reader_get_zip_cd(self, bbuf)))
	return bbuf[0] == 1
end

--reader entry I/O

function reader:open_entry()
	return check(C.mz_zip_reader_entry_open(self))
end

function reader:read(buf, len)
	if buf == '*a' then --NOTE: 2GB max this way!
		local len, err = checklen(C.mz_zip_reader_entry_save_buffer_length(self))
		if not len then return nil, err end
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

function reader_get:entry_is_dir()
	local ret = C.mz_zip_reader_entry_is_dir(self)
	assert(ret >= 0)
	return ret > 0
end

local algorithms = {
	md5    = C.MZ_HASH_MD5   ,
	sha1   = C.MZ_HASH_SHA1  ,
	sha256 = C.MZ_HASH_SHA256,
}

local digest_sizes = {
	md5    = C.MZ_HASH_MD5_SIZE   ,
	sha1   = C.MZ_HASH_SHA1_SIZE  ,
	sha256 = C.MZ_HASH_SHA256_SIZE,
}

function reader:entry_hash(algorithm)
	algorithm = algorithm or 'sha256'
	local digest_size = digest_sizes[algorithm]
	local algorithm = algorithms[algorithm]
	local ok, err = check(C.mz_zip_reader_entry_get_hash(self, algorithm, bbuf, digest_size))
	if not ok then return nil, err end
	return bbuf[0], digest_size --digest, digest_size
end

function reader_get:entry_has_sign()
	local ret = C.mz_zip_reader_entry_has_sign(self)
	assert(ret >= 0)
	return ret > 0
end

function reader:entry_verify_sign()
	return check(C.mz_zip_reader_entry_sign_verify(self))
end

function reader_set:password(password)
	C.mz_zip_reader_set_password(self, password)
end

function reader_set:raw(raw)
	C.mz_zip_reader_set_raw(self, raw)
end

local bbuf = ffi.new'uint8_t[1]'
function reader_get:raw()
	assert(check(C.mz_zip_reader_get_raw(self, bbuf)))
	return bbuf[0] == 1
end

local vbuf = ffi.new'void*[1]'
function reader_get:zip_handle()
	assert(check(C.mz_zip_reader_get_zip_handle(self, vbuf)))
	return vbuf[0]
end

--writer entry catalog & I/O

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

function writer:add_all(dir, root_dir, include_path, recursive)
	return check(C.mz_zip_writer_add_path(self, dir, root_dir,
		include_path or false,
		recursive ~= false))
end

function writer:add_all_from_zip(reader)
	return check(C.mz_zip_writer_copy_from_reader(self, reader))
end

function writer_set:password(password)
	C.mz_zip_writer_set_password(self, password)
end

function writer_set:password(comment)
	C.mz_zip_writer_set_comment(self, comment)
end

function writer_set:raw(raw)
	C.mz_zip_writer_set_raw(self, raw)
end

function writer_get:raw()
	assert(check(C.mz_zip_writer_get_raw(self, bbuf)))
	return bbuf[0] == 1
end

function writer_set:aes(aes)
	C.mz_zip_writer_set_aes(self, aes)
end

function writer_set:compress_method(s)
	C.mz_zip_writer_set_compress_method(self, compression_methods[s])
end

function writer_set:compress_level(level)
	C.mz_zip_writer_set_compress_level(self, level)
end

function writer_set:follow_links(follow)
	C.mz_zip_writer_set_follow_links(self, follow)
end

function writer_set:store_links(store)
	C.mz_zip_writer_set_store_links(self, store)
end

function writer_set:zip_cd(zip_it)
	C.mz_zip_writer_set_zip_cd(self, zip_it)
end

function writer:set_cert(path, pwd)
	assert(check(C.mz_zip_writer_set_certificate(self, path, pwd)))
end

function writer_get:zip_handle()
	assert(check(C.mz_zip_writer_get_zip_handle(self, vbuf)))
	return vbuf[0]
end

ffi.metatype('struct minizip_reader_t', glue.gettersandsetters(reader_get, reader_set, reader))
ffi.metatype('struct minizip_writer_t', glue.gettersandsetters(writer_get, writer_set, writer))

return M
