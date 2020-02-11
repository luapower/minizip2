
local zip = require'minizip2'
local ffi = require'ffi'
local fs = require'fs'

local z = assert(zip.open('media/zip/test-aes.zip', nil, '123'))

print('dir', 'comp', 'mtime', 'atime', 'btime', 'crc',
	'usize', 'csize', 'disknum', 'diskoff', 'ifa', 'efa', 'zip64', 'aesver', 'aes',
	'filename', 'comm', 'link', 'extra')
for e in z:entries() do
	print(
		z.entry_is_dir,
		e.compression_method,
		os.date('!%H:%M', e.mtime),
		os.date('!%H:%M', e.atime),
		os.date('!%H:%M', e.btime),
		e.crc,
		e.compressed_size,
		e.uncompressed_size,
		e.disk_number,
		e.disk_offset,
		e.internal_fa,
		e.external_fa,
		e.zip64,
		e.aes_version,
		e.aes_bits,
		e.filename,
		e.comment,
		e.linkname,
		e.extrafield
	)
	local s, err = z:read'*a'
	assert(not err, err)
	if s then print(string.format('\n%s\n%s\n', e.filename, s)) end
	z:open_entry()
	local buf = ffi.new'char[1]'
	z:read(buf, 1)
	--z:close_entry()
end

assert(z:find'test/a/x/test1.txt')
assert(not z.entry_is_dir)

print''
print('md5   ', z:entry_hash'md5')
print('sha1  ', z:entry_hash'sha1')
print('sha256', z:entry_hash'sha256')

assert(not z.entry_is_dir)
z:open_entry()
assert(not z.entry_has_sign)
print(z:entry_verify_sign())

assert(z:find'test/a/')
assert(z.entry_is_dir)
z:open_entry()
print(pcall(function() return z:entry_has_sign() end)) --directories cannot have signature


assert(z:extract_all'tmp/minizip-test')

z:close()

--xlocal z = zip.open('media/zip/test-aes2.zip', 'w', '123')

assert(fs.remove('tmp/minizip-test', true))

print''
print'done'
