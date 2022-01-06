Here we will create the filesystem backend for the SQLITE 
db file to use the cache filesystem to access the database payload
instead of using the OS filesystem directly

The idea is to "cache" the entry node handle that represents
the db, so we do not need to open every time