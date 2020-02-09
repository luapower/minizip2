
## `local zip = require'minizip2'`

A ffi binding of minizip2, a C library for creating and extracting zip
archives, featuring:

  * reading and writing zip archives from memory.
  * password protection with AES encryption.
  * preserving file attributes and timestamps across file systems.
  * multi-file archives.
  * following and storing symbolic links.
  * utf8 filename support.
  * zipping of central directory to reduce size.
  * generate and verify CMS file signatures.
  * recover the central directory if it is corrupt or missing.

## API

---------------------------------------------------- -------------------------------------------
`zip.open{mode=,file=,...} -> rz|wz`                 open a zip file
`rz:entries() -> iter() -> e`                        iterate entries
`rz:first() -> true|false`                           goto first entry
`rz:next() -> true|false`                            goto next entry
`rz:find(filename[, ignore_case]) -> true|false`     find entry
`rz.is_dir -> true|false`                            is current entry a directory?
`rz.entry -> e`                                      get current entry info
`e.compression_method -> s`                          compression method
`e.mtime -> ts`                                      last modified time
`e.atime -> ts`                                      last accessed time
`e.btime -> ts`                                      creation time
`e.crc -> n`                                         crc-32
`e.compressed_size -> n`                             compressed size
`e.uncompressed_size -> n`                           uncompressed size
`e.disk_number -> n`                                 disk number start
`e.disk_offset -> n`                                 relative offset of local header
`e.internal_fa -> n`                                 internal file attributes
`e.external_fa -> n`                                 external file attributes
`e.filename -> s`                                    filename
`e.extrafield -> s`                                  extrafield data
`e.comment -> s`                                     comment
`e.linkname -> s`                                    sym-link filename
`e.zip64 -> true|false`                              zip64 extension mode
`e.aes_version -> n`                                 winzip aes extension if not 0
`e.aes_encryption_mode -> n`                         winzip aes encryption mode
`rz:extract(to_path)`                                extract current entry to file
`rz:extract_all(to_dir)`                             extract all to dir
`rz:open_entry()`                                    open current entry
`rz:read(buf, maxlen) -> len`                        read from opened entry into a buffer
`rz:read'*a' -> s`                                   read entire entry as string
`rz:close_entry()`                                   close entry
`rz.pattern = s`                                     filter listing entries
`rz.ci_pattern = s`                                  filter listing entries (case insensitive)
`rz.password = s`                                    set password for decryption
`rz.raw = true|false`                                set raw mode
`rz.raw -> true|false`                               get raw mode
`rz.encoding = 'utf8'|codepage`                      support codepages in filenames
`rz.zip_cd -> true|false`                            does the zip have a zipped central directory?
`rz.comment -> s`                                    get comment for the central directory
`wz:add_file(filepath[, filepath_in_zip])`           archive a file
`wz:add_memfile{data=,[len=],filename=,...}`         add a file from a memory buffer
`wz:add_all(dir,[root_dir],[incl_path],[recursive])` add entire dir
`wz:add_all_from_zip(rz)`                            add all entries from other zip file
`wz:set_cert(cert_path[, password])`                 set signing certificate
`rz|wz.zip_handle -> z`                              get C zip handle
`rz|wz:close()`                                      close the zip file
---------------------------------------------------- -------------------------------------------

__NOTE:__ All functions that involve I/O return `nil, err` on error.

### `zip.open(options) -> rz|wz`

The options table has the fields:

-------------- ----------------- ------------ --------------------------------------------------
__key__        __value__         __default__  __meaning__
`mode`         'r|w|a'           'r'          open for reading, writing or appending
`file`         filepath                       open a zip file from disk
`in_memory`    true|false        false        load whole file in memory
`data`         string|buffer                  open a zip file from a memory buffer or string
`len`          number            `#data`      buffer length
`copy`         true|false        false        copy the buffer before loading
`pattern`      string                         filter listing entries
`ci_pattern`   string                         filter listing entries (case insensitive)
`password`     string                         set password for decryption
`raw`          true|false                     set raw mode
`encoding`    'utf8'|codepage                 support codepages in filenames
-------------- ----------------- ------------ --------------------------------------------------

Open a zip file for reading, writing or appending. The zip file bits can come
from the filesystem or from a memory buffer.
