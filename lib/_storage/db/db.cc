// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/db/db.h"

#include "base/optional.h"
#include "base/strings/utf_string_conversions.h"
#include "storage/db/sqlite3.h"
#include "storage/db/sqliteInt.h"
#include "storage/db/btree.h"
#include "storage/db/btreeInt.h"
#include "storage/db/arena.h"
#include "storage/storage_sqlite.h"
#include "storage/io_handler.h"
#include "storage/torrent.h"

#define MEM_Null      0x0001   /* Value is NULL (or a pointer) */
#define MEM_Str       0x0002   /* Value is a string */
#define MEM_Int       0x0004   /* Value is an integer */
#define MEM_Real      0x0008   /* Value is a real number */
#define MEM_Blob      0x0010   /* Value is a BLOB */
#define MEM_AffMask   0x001f   /* Mask of affinity bits */
#define MEM_RowSet    0x0020   /* Value is a RowSet object */
#define MEM_Frame     0x0040   /* Value is a VdbeFrame object */
#define MEM_Undefined 0x0080   /* Value is undefined */
#define MEM_Cleared   0x0100   /* NULL set by OP_Null, not from data */
#define MEM_TypeMask  0xc1ff   /* Mask of type bits */

/* Whenever Mem contains a valid string or blob representation, one of
** the following flags must be set to determine the memory management
** policy for Mem.z.  The MEM_Term flag tells us whether or not the
** string is \000 or \u0000 terminated
*/
#define MEM_Term      0x0200   /* String in Mem.z is zero terminated */
#define MEM_Dyn       0x0400   /* Need to call Mem.xDel() on Mem.z */
#define MEM_Static    0x0800   /* Mem.z points to a static string */
#define MEM_Ephem     0x1000   /* Mem.z points to an ephemeral string */
#define MEM_Agg       0x2000   /* Mem.z points to an agg function context */
#define MEM_Zero      0x4000   /* Mem.i contains count of 0s appended to blob */
#define MEM_Subtype   0x8000   /* Mem.eSubtype is valid */

namespace storage {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

const int SQLITE_BTREE_PAGE_USABLE = 4096 - 8;
const int SQLITE_BTREE_CELL_MAX_LOCAL = (SQLITE_BTREE_PAGE_USABLE - 12) * 64/255 - 23;
//const int SQLITE_BTREE_CELL_MIN_LOCAL = (SQLITE_BTREE_PAGE_USABLE - 12) * 32/255 - 23;

const int SQLITE_FRAGMENT_PRIMARY_PAGE_USABLE = 
  SQLITE_BTREE_CELL_MAX_LOCAL
           - 1 // vdbeRecord header length size
           - 2 // max key length size
           - 4 // max index length size
           - 2; // max value fragment length size

const int SQLITE_FRAGMENT_OVERFLOW_PAGE_USABLE =  SQLITE_BTREE_PAGE_USABLE - 4; // next pageNumber size

const float SQLITE_FRAGMENT_MIN_SAVINGS = 0.20;
  
//namespace {

base::StringPiece Encode(Arena* arena, const KeyValuePair& kv) {
  int keyCode = kv.first.size()*2 + 12;
  int valCode = kv.second.size()*2 + 12;
  //int keyCode = kv.first.size();
  //int valCode = kv.second.size();
  int header_size = csqliteVarintLen(keyCode) + csqliteVarintLen(valCode);
  int hh = csqliteVarintLen(header_size);
  header_size += hh;
  if (hh < csqliteVarintLen(header_size))
    header_size++;
  int size = header_size + kv.first.size() + kv.second.size();

  base::StringPiece v;
  uint8_t* d = reinterpret_cast<uint8_t *>(arena->AllocateBytes(size));//new (v.arena()) uint8_t[size];
  v.set(reinterpret_cast<char *>(d), size);
  //((ValueRef&)v) = KeyRef(d, size);
  d += csqlitePutVarint(d, header_size);
  d += csqlitePutVarint(d, keyCode);
  d += csqlitePutVarint(d, valCode);
  //memcpy(d, &kv.first.begin()[0], kv.first.size());
  memcpy(d, kv.first.begin(), kv.first.size());
  d += kv.first.size();
  //memcpy(d, &kv.second.begin()[0], kv.second.size());
  memcpy(d, kv.second.begin(), kv.second.size());
  d += kv.second.size();
  //DCHECK(d == (uint8_t *)(&v.begin()[0] + size));
  DCHECK(d == (uint8_t *)(v.begin() + size));
  return v;
}

base::StringPiece Stitch(Arena* arena, const KeyValuePair& kv) {
  int size = kv.first.size() + kv.second.size();// + 2;
  base::StringPiece v;
  uint8_t* d = reinterpret_cast<uint8_t *>(arena->AllocateBytes(size));
  v.set(reinterpret_cast<char *>(d), size);
  //memcpy(d, &kv.first.begin()[0], kv.first.size());
  memcpy(d, kv.first.begin(), kv.first.size());
  d += kv.first.size();
  memcpy(d, kv.second.begin(), kv.second.size());
  //d += 0;
  //d += 0;
  //DCHECK(d == (uint8_t *)(v.begin() + size));
  return v;
}

// // Fragments are encoded as (key, index, value) tuples
// // An index of 0 indicates an unfragmented KV pair.
// // For fragmented KV pairs, the values will be concatenated in index order.
// //
// // In the current implementation, index values are chosen to enable a single linear
// // pass over the fragments, in forward or backward order, to immediately know the final
// // unfragmented value size accurately enough to allocate a buffer that is certainly large
// // enough to hold the defragmented bytes.
// //
// // However, the decoder could be made to work if these index value 'hints' become inaccurate
// // due to a change in splitting logic or index numbering.  The decoder would just have to support
// // buffer expansion as needed.
// //
// // Note that changing the following value constitutes a change in index numbering.
#define KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR 4

base::StringPiece EncodeKVFragment(
  Arena* arena,
  const KeyValuePair& kv,
  uint32_t index) {
  int keyCode = kv.first.size()*2 + 12;
  int valCode = kv.second.size()*2 + 12;
  //int keyCode = kv.first.size();
  //int valCode = kv.second.size();
  // The SQLite type code for the index is the minimal number of bytes needed to store
  // a signed representation of the index value.  The type code for 0 is 0 (which is
  // actually the null type in SQLite).
  int8_t indexCode = 0;
  uint32_t tmp = index;
  while(tmp != 0) {
    ++indexCode;
    tmp >>= 8;
  }
  // An increment is required if the high bit of the N-byte index value is set, since it is
  // positive number but SQLite only stores signed values and would interpret it as negative.
  if(index >> (8 * indexCode - 1))
    ++indexCode;

  int header_size = csqliteVarintLen(keyCode) + sizeof(indexCode) + csqliteVarintLen(valCode);
  int hh = csqliteVarintLen(header_size);
  header_size += hh;
  if (hh < csqliteVarintLen(header_size))
    header_size++;
  int size = header_size + kv.first.size() + indexCode + kv.second.size();

  base::StringPiece v;
  uint8_t* d = reinterpret_cast<uint8_t *>(arena->AllocateBytes(size));
  //((ValueRef&)v) = KeyRef(d, size);
  v.set(reinterpret_cast<char *>(d), size);
  d += csqlitePutVarint(d, header_size);
  d += csqlitePutVarint(d, keyCode);
  *d++ = indexCode;
  d += csqlitePutVarint(d, valCode);

  // Write key
  //memcpy(d, &kv.first.begin()[0], kv.first.size());
  memcpy(d, kv.first.begin(), kv.first.size());
  d += kv.first.size();

  // Write index bytes, if any
  for(int i = indexCode - 1; i >= 0; --i) {
    d[i] = (uint8_t)index;
    index >>= 8;
  }
  d += indexCode;

  // Write value
  memcpy(d, kv.second.begin(), kv.second.size());
  d += kv.second.size();
  //DCHECK(d == (uint8_t *)(&v.begin()[0] + size));
  DCHECK(d == (uint8_t *)(v.begin() + size));
  return v;
}

int GetEncodedSize(int keySize, int valuePrefixSize) {
   int keyCode = keySize*2 + 12;
   //int keyCode = keySize;
   int header_size = csqliteVarintLen(keyCode) + 8; // 8 is the maximum return value of csqliteVarintLen(), so this is our worst case header size (for values larger than allowable database values)
   int hh = csqliteVarintLen(header_size);
   header_size += hh;
   if (hh < csqliteVarintLen(header_size))
     header_size++;
   return header_size + keySize + valuePrefixSize;
}

// // Given a key size and value prefix size, get the minimum bytes that must be read from the underlying
// // btree tuple to safely read the prefix length from the value bytes (if the value is long enough)
int GetEncodedKVFragmentSize(int keySize, int valuePrefixSize) {
  int keyCode = keySize*2 + 12;
  //int keyCode = keySize;
  int header_size = csqliteVarintLen(keyCode)
        + 1  // index code length
        + 8; // worst case for value size (larger than fdb api allows)
  int hh = csqliteVarintLen(header_size);
  header_size += hh;
  if (hh < csqliteVarintLen(header_size))
    header_size++;
  return header_size + keySize
    + 4  // Max width allowed of index value
    + valuePrefixSize;
}

// // Decode (key, index, value) tuple.
// // A present() Optional will always be returned UNLESS partial is true.
// // If partial is true then the return will not be present() unless at least
// // the full key and index were in the encoded buffer.  The value returned will be 0 or
// // more value bytes, however many were available.
// // Note that a short encoded buffer must at *least* contain the header length varint.
KeyValuePair DecodeKVFragment(base::StringPiece encoded, uint32_t *index = NULL, bool partial = false) {
  uint8_t const* d = reinterpret_cast<uint8_t const*>(encoded.begin());
  uint64_t h, len1, len2;
  d += csqliteGetVarint( d, (u64*)&h );

  // Make sure entire header is present, else return nothing
  if (partial && encoded.size() < h) {
    DLOG(ERROR) << "bad payload: h [" << h << "] != size [" << encoded.size() << "]";
    return KeyValuePair();
  }

  d += csqliteGetVarint(d, (u64*)&len1);
  const uint8_t indexLen = *d++;
  DCHECK(indexLen <= 4);
  d += csqliteGetVarint(d, (u64*)&len2);
  DCHECK(d == reinterpret_cast<uint8_t const*>(encoded.begin() + h));
  DCHECK(len1 >= 12 && !(len1&1));
  DCHECK(len2 >= 12 && !(len2&1));
  len1 = (len1-12) / 2;
  len2 = (len2-12) / 2;


  if (partial) {
    // If the key and index aren't complete, return nothing.
    if(d + len1 + indexLen > reinterpret_cast<uint8_t const*>(encoded.end())) {
      DLOG(ERROR) << "bad payload: d + len1 + indexLen [" << d + len1 + indexLen << "] > encoded.end() [" << encoded.end() << "]";
      return KeyValuePair();
    }
    // Encoded size shouldn't be *larger* than the record described by the header no matter what.
    DCHECK(d + len1 + indexLen + len2 >= reinterpret_cast<uint8_t const*>(encoded.end()));
    // Shorten value length to be whatever bytes remain after the header/key/index
    len2 = std::min(len2, (uint64_t)(reinterpret_cast<uint8_t const*>(encoded.end()) - indexLen - len1 - d));
  }
  else {
    // But for non partial records encoded size should be exactly the size of the described record.
    CHECK(d + len1 + indexLen + len2 == reinterpret_cast<uint8_t const*>(encoded.end()));
  }

  // Decode big endian index
  if(index != nullptr) {
    if(indexLen == 0)
      *index = 0;
    else {
      const uint8_t *begin = d + len1;
      const uint8_t *end = begin + indexLen;
      *index = (uint8_t)*begin++;
      while(begin < end) {
        *index <<= 8;
        *index |= *begin++;
      }
    }
  }
  return std::make_pair(base::StringPiece(reinterpret_cast<char const*>(d), len1), base::StringPiece(reinterpret_cast<char const*>(d + len1 + indexLen), len2));
}

KeyValuePair DecodeKVPrefix(base::StringPiece encoded, int maxLength) {
  uint8_t const* d = reinterpret_cast<uint8_t const*>(encoded.begin());
  uint64_t h, len1, len2;
  d += csqliteGetVarint(d, (u64*)&h);
  d += csqliteGetVarint(d, (u64*)&len1);
  d += csqliteGetVarint(d, (u64*)&len2);
  DCHECK(d == reinterpret_cast<uint8_t const*>(encoded.begin()) + h );
  DCHECK(len1 >= 12 && !(len1&1) );
  DCHECK(len2 >= 12 && !(len2&1) );
  len1 = (len1-12)/2;
  len2 = (len2-12)/2;
  len2 = std::min(len2, (uint64_t)maxLength);
  DCHECK(d + len1 + len2 <= reinterpret_cast<uint8_t const*>(encoded.end()));
  return std::make_pair(base::StringPiece(reinterpret_cast<char const*>(d), len1), base::StringPiece(reinterpret_cast<char const*>(d + len1), len2));
}

base::StringPiece EncodeKey(Arena* arena, base::StringPiece key, bool using_fragments) {
  int keyCode = key.size()*2 + 12;
  //int keyCode = key.size();
  int header_size = csqliteVarintLen(keyCode);
  if (using_fragments)  // will be encoded as key, 0  (where 0 is really a null)
    ++header_size;
  int hh = csqliteVarintLen(header_size);
  header_size += hh;
  if (hh < csqliteVarintLen(header_size))
    header_size++;
  int size = header_size + key.size();
  base::StringPiece v;
  uint8_t* d = reinterpret_cast<uint8_t *>(arena->AllocateBytes(size));//new (v.arena()) uint8_t[size];
  //((ValueRef&)v) = KeyRef(d, size);
  v.set(reinterpret_cast<char *>(d), size);
  d += csqlitePutVarint(d, header_size);
  d += csqlitePutVarint(d, keyCode);
  if(using_fragments)
    *d++ = 0;
  memcpy(d, key.begin(), key.size());
  d += key.size();
  DCHECK(d == reinterpret_cast<const uint8_t *>(v.begin()) + size);
  return v;
}

// Once either method returns a non-present value, using the DefragmentingReader again is undefined behavior.
class DefragmentingReader {
public:
  // Use this constructor for forward/backward range reads
  DefragmentingReader(Cursor* cur, Arena* arena, bool forward): 
    cur_(cur),
    arena_(arena), 
    forward_(forward), 
    fragmentReadLimit_(-1) {
      Parse();
  }

  // Use this constructor to read a SINGLE partial value from the current cursor position for an expected key.
  // This exists to support IKeyValueStore::getPrefix().
  // The reader will return exactly one KV pair if its key matches expectedKey, otherwise no KV pairs.
  DefragmentingReader(Cursor* cur, Arena* arena, base::StringPiece expectedKey, int maxValueLen): 
    cur_(cur), 
    arena_(arena), 
    forward_(true), 
    maxValueLen_(maxValueLen) {
    
    fragmentReadLimit_ = GetEncodedKVFragmentSize(expectedKey.size(), maxValueLen);
    Parse();
    // If a key was found but it wasn't the expected key then
    // clear the current kv pair and invalidate the cursor.
    if(kv_ && kv_.value().first != expectedKey) {
      DLOG(INFO) << "not the expected key: " << kv_.value().first << " vs " << expectedKey;
      kv_ = base::Optional<KeyValuePair>();
      cur_->SetValid(false);
    }
  }

  // Get the next key that would be returned by getNext(), if there is one
  // This is more efficient than getNext() if the caller is not sure if it wants the next KV pair
  base::Optional<base::StringPiece> Peek() {
    if (kv_) {
      return kv_.value().first;
    }
    return base::Optional<base::StringPiece>();
    //return Advance();
  }

  base::Optional<KeyValuePair> GetNext() {
    if(!Peek()) {
      return base::Optional<KeyValuePair>();
    }

    bool partial = fragmentReadLimit_ >= 0;

    // Start out with the next KV fragment as the pair to return
    KeyValuePair resultKV = kv_.value();

    // If index is 0 then this is an unfragmented key.  It is unnecessary to advance the cursor so
    // we won't, but we will clear kv so that the next peek/getNext will have to advance.
    if (index_ == 0) {
      kv_ = base::Optional<KeyValuePair>();
    } else {
      
      // First and last indexes in fragment group are size hints.
      //   First index is ceil(total_value_size / 4)
      //   Last  index is ceil(total_value_size / 2)
      // Set size depending on which of these will be first encountered and allocate buffer in arena.
      // Note that if these index hints are wrong (such as if the index scheme changes) then asserts
      // below will fail.  They will have to be changed to expand the buffer as needed.
      int size = forward_ ? (index_ * (KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR / 2)) : (index_ * KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR);
      uint8_t *buf = reinterpret_cast<uint8_t *>(arena_->AllocateBytes(size));//new (arena) uint8_t[size];
      uint8_t *bufEnd = buf + size;
      // For forward iteration wptr is the place to write to next, for reverse it's where the last write started.
      uint8_t *wptr = !forward_ ? buf : bufEnd;
      int fragments = 0;
      do {
        ++fragments;
        base::StringPiece val = kv_.value().second;
        if (forward_) {
          wptr -= val.size();
          DCHECK(wptr >= buf);
          memcpy(wptr, val.begin(), val.size());
        } else {
          uint8_t *w = wptr;
          wptr += val.size();
          DCHECK(wptr <= bufEnd);
          memcpy(w, val.begin(), val.size());
          // If this is a partial value get and we have enough bytes we can stop since we are forward iterating.
          if (partial && wptr - buf >= maxValueLen_) {
            resultKV.second = base::StringPiece(reinterpret_cast<char *>(buf), maxValueLen_);
            // To make further calls to peek() or getNext() return nothing, reset kv and invalidate cursor
            kv_ = base::Optional<KeyValuePair>();
            cur_->SetValid(false);
            return resultKV;
          }
        }
      } while(Advance() && kv_.value().first == resultKV.first);

      // If there was only 1 fragment, it should have been index 0 and handled above,
      DCHECK(fragments != 1);
      // Set final value based on direction of buffer fill
      resultKV.second = forward_ ? 
        base::StringPiece(reinterpret_cast<char *>(wptr), bufEnd - wptr) :
        base::StringPiece(reinterpret_cast<char *>(buf), wptr - buf);
    }

    // In partial value mode, we could end up here if there was only 1 fragments or maxValueLen
    // was greater than the total unfragmented value size.
    if (partial) {
      resultKV.second = resultKV.second.substr(0, std::min((int)resultKV.second.size(), maxValueLen_));
    }
    return resultKV;
  }

private:
  // Update kv with whatever is at the current cursor position if the position is valid.
  void Parse() {
    if (cur_->IsValid()) {
      // The read is either not partial or it is but the fragment read limit is at least 4 (the size of a minimal header).
      bool partial = fragmentReadLimit_ >= 0;
      DCHECK(!partial || fragmentReadLimit_ >= 4);
      // Read full or part of fragment
      base::StringPiece encoded = (partial) ? cur_->GetDataPrefix(fragmentReadLimit_) : cur_->GetData();
      kv_ = DecodeKVFragment(encoded, &index_, partial);
      printf("decoded index: %d\n", index_);
      // If this was a partial fragment then if successful update the next fragment read size, and if not
      // then invalidate the cursor.
      if(partial) {
        if(kv_) {
          fragmentReadLimit_ -= kv_.value().second.size();
        } else {
          cur_->SetValid(false);
        }
      }
    } else {
      kv_ = base::Optional<KeyValuePair>();
    }
  }

  // advance cursor, parse and return key if valid
  base::Optional<base::StringPiece> Advance() {
    if (cur_->IsValid()) {
      forward_ ? cur_->Next() : cur_->Previous();
      Parse();
    }
    return kv_ ? kv_.value().first : base::Optional<base::StringPiece>();
  }

  base::Optional<KeyValuePair> kv_;  // key and latest value fragment read
  uint32_t index_;            // index of latest value fragment read
  Cursor* cur_;            // Cursor to read from
  Arena* arena_;              // Arena to allocate key and value bytes in
  bool forward_;              // true for forward iteration, false for reverse
  int maxValueLen_;           // truncated value length to return
  int fragmentReadLimit_;     // If >= 0, only read and *attempt* to decode this many fragment bytes
};


//} // namespace

#pragma clang diagnostic pop

// DBEncoder::DBEncoder() {

// }

// void DBEncoder::EncodeString(base::StringPiece* value) {

// }

Cursor::Cursor(Database* db, Transaction* transaction, const std::string& keyspace, int table, Order order):
  db_(db),
  transaction_(transaction),
  arena_(new Arena(&allocator_, 0, std::numeric_limits<size_t>::max())),
  valid_(false),
  nfield_(1),
  keyspace_(keyspace),
  //match_equals_(false),
  order_(order) {

  keyInfo_ = (KeyInfo *)malloc(sizeof(struct KeyInfo));  

  memset(keyInfo_, 0, sizeof(KeyInfo));

  keyInfo_->db = db_->sqlite_;
  keyInfo_->enc = db_->sqlite_->aDb[0].pSchema->enc;
  keyInfo_->aColl[0] = db_->sqlite_->pDfltColl;
  keyInfo_->aSortOrder = reinterpret_cast<u8 *>(malloc(sizeof(u8) * nfield_ + 1));
  keyInfo_->nKeyField = nfield_;
  keyInfo_->nAllField = nfield_;

  for (int i = 0; i < nfield_ + 1; i++) {
    keyInfo_->aSortOrder[i] = (order == Order::ASC ? SQLITE_SO_ASC : SQLITE_SO_DESC);
  }

  handle_ = reinterpret_cast<BtCursor *>(malloc(csqliteBtreeCursorSize()));
  csqliteBtreeCursorZero(handle_);

  //int rc = csqliteBtregeCursor(db_-tab>btree_, db_->freetable_, BTREE_WRCSR, &keyInfo_, handle_);
  DLOG(INFO) << "creating cursor for table " << table << " = " << db_->tables_[table];
  int rc = csqliteBtreeCursor(db_->btree_, db_->tables_[table], transaction_->write() ? BTREE_WRCSR : BTREE_FORDELETE, keyInfo_, handle_);
  if (rc != SQLITE_OK) {
    LOG(ERROR) << "csqliteBtreeCursor: rc = " << rc;
  }

  //csqliteBtreeCursorHintFlags(handle_, BTREE_BULKLOAD);
}

Cursor::~Cursor() {
  csqliteBtreeCloseCursor(handle_);
  free(keyInfo_->aSortOrder);
  free(keyInfo_);
  free(handle_);
}

bool Cursor::IsValid() const {
  return handle_->eState == CURSOR_VALID;
  //return valid_;
}

bool Cursor::IsEof() const {
  int eof = csqliteBtreeEof(handle_);
  return eof;
}

void Cursor::First() {
  int empty = 1;
  int rc = csqliteBtreeFirst(handle_, &empty);
  valid_ = rc == 0;//!empty;
}

void Cursor::Last() {
  int empty = 1;
  int rc = csqliteBtreeLast(handle_, &empty);
  valid_ = rc == 0; //!empty;
}

void Cursor::Previous() {
  int rc = csqliteBtreePrevious(handle_, 0);
  valid_ = rc == 0;
}

void Cursor::Next() {
  int rc = csqliteBtreeNext(handle_, 0);
  valid_ = rc != 101;
}

int64_t Cursor::Count() const {
  int64_t r = static_cast<int64_t>(csqliteBtreeRowCountEst(handle_));
  return r;
}

int64_t Cursor::IntKey() const {
  int64_t r =static_cast<int64_t>(csqliteBtreeIntegerKey(handle_));
  return r;
}

size_t Cursor::DataSize() const {
  size_t sz = csqliteBtreePayloadSize(handle_);
  return sz;
}

//bool Cursor::Update(base::StringPiece value) {
//  return false;
//}

bool Cursor::HasValue(base::StringPiece key, bool* result) {
  bool match = false;
  int r = SeekTo(key, Seek::EQ, &match);
  if ((r == 0 && match) || match) {
    *result = true;
  } else {
    *result = false;
  }
  return true;
}

bool Cursor::GetValue(base::StringPiece key, base::StringPiece* data) {
  bool match = false;
  csqliteBtreeEnter(db_->btree_);
  int r = SeekTo(key, Seek::EQ, &match);
  csqliteBtreeLeave(db_->btree_);
  if(db_->fragment_values_) {
    if (r == 0 || match) {
      KeyValuePair kv = DecodeKVFragment(GetData());
      *data = kv.second;
      return true;
    }
    DefragmentingReader i(this, arena_.get(), true);
    //DLOG(INFO) << i.Peek().value() << " == " << key;
    if (i.Peek() == key) {
      base::Optional<KeyValuePair> kv = i.GetNext();
      *data = kv.value().second;
      return true;
    }
  } else if (r >= 0) {
    if (!match) {
      return false;
    }
    bool valid = false;
    KeyValuePair kv = DbDecodeKV(GetData(), &valid);
    if (valid) {
      *data = kv.second;
      return true;
    }
  }

  return false;
}

bool Cursor::Get(base::StringPiece key, KeyValuePair* kv) {
  bool match = false;
  int r = SeekTo(key, Seek::EQ, &match);

  if (db_->fragment_values_) {
    if(r == 0 || match) {
      KeyValuePair data = DecodeKVFragment(GetData());
      *kv = data;
      return true;
    }

    DefragmentingReader i(this, arena_.get(), true);
    if(i.Peek() == key) {
      base::Optional<KeyValuePair> data = i.GetNext();
      *kv = data.value();
      return true;
    }
  } else if (r >= 0) {
    if (!match) {
      return false;
    }
    bool valid = false;
    KeyValuePair data = DbDecodeKV(GetData(), &valid);
    if (valid) {
      *kv = data;
      return true;
    }
  }

  return false;
}

base::StringPiece Cursor::GetPrefix(base::StringPiece key, int maxLength) {
  bool match = false;

  if (db_->fragment_values_) {
    int r = SeekTo(key, Seek::EQ, &match);
    
    if (r < 0) {
      Next();
    }

    DefragmentingReader i(this, arena_.get(), GetEncodedKVFragmentSize(key.size(), maxLength));
    if (i.Peek() == key) {
      base::Optional<KeyValuePair> kv = i.GetNext();
      return kv.value().second;
    }

  } else if (!SeekTo(key, Seek::EQ, &match)) {
    if (maxLength == 0) {
      return base::StringPiece();
    }
    int maxEncodedSize = GetEncodedSize(key.size(), maxLength);
    KeyValuePair kv = DecodeKVPrefix(GetDataPrefix(maxEncodedSize), maxLength);
    return kv.second;
  }

  return base::StringPiece();
}

bool Cursor::Delete() {
  return csqliteBtreeDelete(handle_, BTREE_SAVEPOSITION) == SQLITE_OK;
}

int Cursor::SeekTo(base::StringPiece key, Seek seek, bool* match, bool ignore_fragment_mode) {
  // we only use EQ to test for perfect match. otherwise EQ works more like LE
  //Seek rseek = (seek == Seek::EQ ? Seek::GE : seek);

  UnpackedRecord r;
  r.pKeyInfo = keyInfo_;
  r.errCode = 0;
  r.r1 = 0;
  r.r2 = 0;
  r.eqSeen = 0;
  r.default_rc = 0;

  //if (seek == Seek::GT || seek == Seek::LE) {
  //  r.default_rc = -1;
  //} else if (seek != Seek::EQ) {
  //  r.default_rc = +1;
  //}
  
  csqlite_value tupleValues[2];

  memset(tupleValues, 0, sizeof(csqlite_value) * 2);
  
  int len = 12 + (2 * key.size());
  //int len = key.size();
 
  tupleValues[0].db = keyInfo_->db;
  tupleValues[0].enc = keyInfo_->enc;
  tupleValues[0].zMalloc = NULL;
  tupleValues[0].z = const_cast<char *>(key.begin());
  tupleValues[0].n = (len - 12) / 2; // 12 + (2 * key.size())
  tupleValues[0].flags = MEM_Blob | MEM_Ephem;
      
  if (ignore_fragment_mode || !db_->fragment_values_) {
    r.nField = 1;
  } else {
    // Set field 2 of tuple to the null type which is typecode 0
    tupleValues[1].db = keyInfo_->db;
    tupleValues[1].enc = keyInfo_->enc;
    tupleValues[1].zMalloc = NULL;
    DCHECK(csqliteVdbeSerialGet(NULL, 0, &tupleValues[1]) == 0);
    r.nField = 2;
  }

  int result = -999;

  r.aMem = &tupleValues[0];

  csqlite_mutex_enter(handle_->pBtree->db->mutex);
  //csqliteBtreeEnter(db_->btree_);
  int rc = csqliteBtreeMovetoUnpacked(handle_, &r, 0, 0, &result);
  csqlite_mutex_leave(handle_->pBtree->db->mutex);
  //csqliteBtreeLeave(db_->btree_);

  DCHECK(rc == 0);
 
  if (r.eqSeen == 1) {
    *match = true;
  } else {
    *match = false;
  }

  //if (should_match && !match_equals_) {
  //  base::StringPiece data = GetData();
  //  printf("not found! data: '%s'\n", (data.size() ? data.as_string().c_str() : "(null)"));
    //result = -1;
  //}

  // if (rseek == Seek::GT || rseek == Seek::GE) {
  //   if ((result < 0 && !db_->fragment_values_) || (result ==0 && rseek == Seek::GT)) {
  //     //result = 0;
  //     rc = csqliteBtreeNext(handle_, 0);
  //     if (rc != SQLITE_OK) {
  //       if (rc == SQLITE_DONE){
  //         rc = SQLITE_OK;
  //         //result = 1;
  //       } else {
  //         printf("error! rc: %d\n", rc);
  //         //goto abort_due_to_error;
  //         return result;
  //       }
  //     }
  //   } //else {
  //   //  result = 0;
  //   //}
  // } else if (rseek == Seek::LT || rseek == Seek::LE) {
  //   if (result > 0 || (result == 0 && rseek == Seek::LT)) {
  //     //result = 0;
  //     rc = csqliteBtreePrevious(handle_, 0);
  //     if (rc !=SQLITE_OK) {
  //       if (rc == SQLITE_DONE) {
  //         rc = SQLITE_OK;
  //       //  result = 1;
  //       } else {
  //         printf("error! rc: %d\n", rc);
  //         return result;
  //       }
  //     }
  //   } else {
  //     /* res might be negative because the table is empty.  Check to
  //     ** see if this is the case.
  //     */
  //     result = csqliteBtreeEof(handle_);
  //   }
  // }

  // workaround for when theres no results
  //if (result == -1) {
  //  result = csqliteBtreeEof(handle_);
  //}

  return result;
}

base::StringPiece Cursor::GetData() {
  int s = csqliteBtreePayloadSize(handle_);
  if (s > 0) {
    uint8_t* d = reinterpret_cast<uint8_t *>(arena_->AllocateBytes(s));
    int rc = csqliteBtreePayload(handle_, 0, s, d);
    DCHECK(rc == 0);
    return base::StringPiece(reinterpret_cast<char *>(d), s);
  }
  return base::StringPiece();
}

base::StringPiece Cursor::GetDataPrefix(int max_encoded_size) {
  int s = std::min((int)csqliteBtreePayloadSize(handle_), max_encoded_size);
  uint8_t* d = reinterpret_cast<uint8_t *>(arena_->AllocateBytes(s));
  int rc = csqliteBtreePayload(handle_, 0, s, d);
  DCHECK(rc == 0);
  return base::StringPiece(reinterpret_cast<char *>(d), s);
}

bool Cursor::Insert(const KeyValuePair& kv) {
  bool result = false;
  if (db_->fragment_values_) {
    bool match = false;
    // Unlike a read, where we need to access fragments in fully forward or reverse order,
    // here we just want to delete any existing fragments for the key.  It does not matter
    // what order we delete them in, and SQLite requires us to seek after every delete, so
    // the fastest way to do this is to repeatedly seek to the tuple prefix (key, ) and
    // delete the current fragment until nothing is there.
    // This should result in almost identical performance to non-fragmenting mode for single fragment kv pairs.
    int seekResult = SeekTo(kv.first, Seek::EQ, &match, true);   // second arg means to ignore fragmenting and seek to (key, )
    while (seekResult == 0) {
      Delete();
      seekResult = SeekTo(kv.first, Seek::EQ, &match, true);
    }

    const int primaryPageUsable = SQLITE_FRAGMENT_PRIMARY_PAGE_USABLE;
    const int overflowPageUsable = SQLITE_FRAGMENT_OVERFLOW_PAGE_USABLE;

    int fragments = 1;
    int valuePerFragment = kv.second.size();

    // Figure out if we would benefit from fragmenting this kv pair.  The key size must be less than
    // primary page usable size, and the value and key size together must exceeed the primary page usable size.
    if ((kv.first.size() + kv.second.size()) > primaryPageUsable
       && kv.first.size() < primaryPageUsable) {

      // Just the part of the value that would be in a partially-filled overflow page
      int overflowPartialBytes = ((kv.first.size() + kv.second.size()) - primaryPageUsable) % overflowPageUsable;

      // Number of bytes wasted in the unfragmented case
      int unfragmentedWaste = overflowPageUsable - overflowPartialBytes;

      // Total space used for unfragmented form
      int unfragmentedTotal = (kv.first.size() + kv.second.size()) + unfragmentedWaste;

      // Value bytes that can fit in the primary page for each fragment
      int primaryPageValueBytes = primaryPageUsable - kv.first.size();

      // Calculate how many total fragments it would take to spread the partial overflow page bytes and the first fragment's primary
      // page value bytes evenly over multiple tuples that fit in primary pages.
      fragments = (primaryPageValueBytes + overflowPartialBytes + primaryPageValueBytes - 1) / primaryPageValueBytes;

      // Number of bytes wasted in the fragmented case (for the extra key copies)
      int fragmentedWaste = kv.first.size() * (fragments - 1);

      // Total bytes used for the fragmented case
      //int fragmentedTotal = (kv.first.size() + kv.second.size()) + fragmentedWaste;

      // Calculate bytes saved by having extra key instances stored vs the original partial overflow page bytes.
      int savings = unfragmentedWaste - fragmentedWaste;

      double reduction = (double)savings / unfragmentedTotal;

      //printf("K: %5d  V: %6d  OVERFLOW: %5d  FRAGMENTS: %3d  SAVINGS: %4d  FRAG: %7d  UNFRAG: %7d  REDUCTION: %.3f\n",
      //  (int)kv.first.size(), (int)kv.second.size(), overflowPartialBytes, fragments, savings, fragmentedTotal, unfragmentedTotal, reduction);
      if (reduction < SQLITE_FRAGMENT_MIN_SAVINGS) {
        fragments = 1;
      } else {
        valuePerFragment = (primaryPageValueBytes + overflowPartialBytes + fragments - 1) / fragments;
      }
    }

    if (fragments == 1) {
      return InsertFragment(kv, 0, seekResult);
    }

    // First index is ceiling(value_size / KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR)
    uint32_t nextIndex = (kv.second.size() + KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR - 1) / KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR;
    // Last index is ceiling(value_size / (KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR / 2) )
    uint32_t finalIndex = (kv.second.size() + (KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR / 2) - 1) / (KV_FRAGMENT_INDEX_SIZE_HINT_FACTOR / 2);
    int bytesLeft = kv.second.size();
    int readPos = 0;
  
    while (bytesLeft > 0) {
      --fragments;  // remaining ideal fragment count
      int fragSize = (fragments == 0) ? bytesLeft : std::min<int>(bytesLeft, valuePerFragment);

      // The last fragment must have an index of finalIndex or higher.
      if (fragSize == bytesLeft && nextIndex < finalIndex) {
        nextIndex = finalIndex;
      }
      //printf("seekResult: %d\n", seekResult);
      //printf("insert ks %zu vs %zu  fragment %d, %dbytes\n", kv.first.size(), kv.second.size(), nextIndex, fragSize);
      result = InsertFragment(KeyValuePair(kv.first, kv.second.substr(readPos, fragSize)), nextIndex, seekResult);
      // 
      //if (result && seekResult == -1) {
      //  seekResult = 1;//SeekTo(kv.first, Seek::EQ, true);
      //}
      // seekResult can only be used for the first insertion.
      //if(seekResult != 0) {
      //  seekResult = 0;
      //}
      readPos += fragSize;
      bytesLeft -= fragSize;
      ++nextIndex;
    }
  }
  else {
    bool match = false;
    int r = SeekTo(kv.first, Seek::EQ, &match);
    /*
     * Note: Depending on the thread heuristics consuming
     *       this, this might change
     *       If this is more sequencial than use the match boolean
     *       to test. If is more parallel, that the r == 0 must be used
     *       as a sign that theres a match for the given value.
     *       I dont know why SQLite btree changes its behaviour
     *       for this depending on the multi-threaded logic one's using
     */
    if (match) { /* for sequential threading */
 /* if (r == 0) { for parallel threading */
      LOG(INFO) << "match ? " << match << " r = " << r << " -**- INSERT: '" << kv.first << "' [" << kv.first.size() << "] matched, so we are deleting current pos first. to change for new value -**-";
      Delete();
    } else {
      LOG(INFO) << "match ? " << match << " r = " << r << " -**- INSERT: '" << kv.first << "' [" << kv.first.size() << "] does not match. nothing to delete -**-";
    }
    base::StringPiece v = Encode(arena_.get(), kv);
    
    //printf("k: '%s' [%zu] v: '%s' [%zu] encoded:'%s' [%zu]\n", kv.first.as_string().c_str(), kv.first.size(), kv.second.as_string().c_str(), kv.second.size(), v.as_string().c_str(), v.size());

    BtreePayload record;
    csqlite_value val[1];

    memset(val, 0, sizeof(csqlite_value));
    
    val[0].flags = MEM_Blob;
    val[0].n = v.size();
    val[0].enc = keyInfo_->enc;
    val[0].z = (char *)v.begin();

    record.pKey = v.begin();
    record.nKey = v.size();
    record.aMem = val;
    record.nMem = 1;
    record.pData = 0;
    record.nData = 0;
    record.nZero = 0;

    int rc = csqliteBtreeInsert(handle_, &record, 0, r);
    return rc == SQLITE_OK;
  }

  return result;
}

bool Cursor::InsertFragment(const KeyValuePair& kv, uint32_t index, int seek_result) {
  base::StringPiece v = EncodeKVFragment(arena_.get(), kv, index);
  BtreePayload record;

  csqlite_value val[1];
  memset(val, 0, sizeof(csqlite_value));

  val[0].flags = MEM_Blob;
  val[0].n = v.size();
  val[0].enc = keyInfo_->enc;
  val[0].z = (char *)v.begin();

  record.pKey = v.begin();
  record.nKey = v.size();
  record.aMem = val;
  record.nMem = 1;
  record.pData = 0;
  record.nData = 0;
  record.nZero = 0;

  int rc = csqliteBtreeInsert(handle_, &record, 0, seek_result);
  return rc == SQLITE_OK;
}

void Cursor::SetValid(bool valid) {
  valid_ = valid;
}

Transaction::Transaction(Database* db, bool write): 
  db_(db),
  write_(write) {

}

Transaction::~Transaction() {

}

void Transaction::Commit() {
  int rc = SQLITE_OK;
  csqliteBtreeEnter(db_->btree_);
  //if (write_) {
    rc = csqliteBtreeCommitPhaseOne(db_->btree_, 0);
    if (rc != SQLITE_OK) { LOG(ERROR) << "csqliteBtreeCommitPhaseOne error: " << rc; }
  //}
  if (rc == SQLITE_OK) {
    rc = csqliteBtreeCommitPhaseTwo(db_->btree_, 0);
    if (rc != SQLITE_OK) { LOG(ERROR) << "csqliteBtreeCommitPhaseTwo error: " << rc; }
  }
  csqliteBtreeLeave(db_->btree_);
}

void Transaction::Rollback() {
  csqliteBtreeRollback(db_->btree_, 0, 0);
}  

Database::Database(              
  const base::UUID& id,
  csqlite* sqlite, 
  Btree* btree,
  int table_count): 
    sqlite_(sqlite), 
    btree_(btree),
    id_(id),
    table_count_(table_count),
    readonly_(false),
    fragment_values_(false),
    largest_root_page_(0),
    closed_(false) {
  
}

Database::~Database() {
  if (!closed_) {
    Close();
  }
}

bool Database::CreateTables(const std::vector<std::string>& keyspaces) {
  DCHECK(keyspaces.size() == table_count_);
  DCHECK(ExecuteStatement("PRAGMA page_size = 65536"));
  DCHECK(ExecuteStatement("PRAGMA auto_vacuum = 2"));
  DCHECK(ExecuteStatement("PRAGMA journal_mode=WAL"));
  ExecuteStatement("PRAGMA wal_autocheckpoint=4096");
  ExecuteStatement("PRAGMA synchronous = FULL"); 
  ExecuteStatement("PRAGMA locking_mode=EXCLUSIVE");

  csqlite_extended_result_codes(sqlite_, 1);

  auto trans = BeginTransaction(true);
  if (!trans) {
    LOG(ERROR) << "Database::CreateTables: fatal, create write btree transaction failed";
    return false;
  }
  
  csqliteBtreeGetMeta(btree_, BTREE_LARGEST_ROOT_PAGE, &largest_root_page_);
  DLOG(ERROR) << "create tables. table count: " << table_count_ << " pgnoRoot: " << largest_root_page_;
  if (largest_root_page_ == 4) {
    u32 start = largest_root_page_-1;
    tables_[0] = start;
    if (table_count_ > 1) {
      size_t table_count = table_count_ - 1;
      for (size_t i = 0; i < table_count; i++) {
        tables_[i+1] = start + (i + 1);
      }
    }
    trans->Rollback();
  } else if (largest_root_page_ == 1){
    for (int i = 0; i < table_count_; i++) {
      csqliteBtreeCreateTable(btree_, &tables_[i], BTREE_BLOBKEY);
    }
    trans->Commit();
  } else {
    int tables = table_count_ + 1;//(table_count_ == 1 ? 1 : 0);//table_count_ == 1 ? 2 : table_count_;
    for (int i = 0; i < tables; i++) {
      int rc = csqliteBtreeCreateTable(btree_, &tables_[i], BTREE_BLOBKEY);
      if (rc != SQLITE_OK) {
        DLOG(ERROR) << "failed creating btree table index " << i << ". error = " << rc;
      }
      DLOG(INFO) << ": created table " << i << " page: " << tables_[i]; 
    }
    
    //DLOG(INFO) << "updating pgnoRoot ..";
    //csqliteBtreeGetMeta(btree_, BTREE_LARGEST_ROOT_PAGE, &pgnoRoot);  
    
    DLOG(INFO) << ": calling update meta ... pgnoRoot: " << largest_root_page_ << " with value: " << tables_[0];
    int rc = csqliteBtreeUpdateMeta(btree_, BTREE_LARGEST_ROOT_PAGE, tables_[0]);
    if (rc != SQLITE_OK) {
      DLOG(ERROR) << "csqliteBtreeUpdateMeta failed. error = " << rc;
    } else {
      // if update was ok, we manually set our own copy
      largest_root_page_ = tables_[0];
    }
    

    trans->Commit();

    // now push the keyspaces (we expect they are in order)
    // into the table 0

    auto tr2 = BeginTransaction(true);
    if (!tr2) {
      LOG(ERROR) << "Database::CreateTables: fatal, create write btree transaction failed";
      return false;
    } 

    Cursor c(this, tr2.get(), "", 0);

    for (int i = 0; i < table_count_; ++i) {
      // save the index into the value
      int ilen = csqliteVarintLen(i+1);
      base::StringPiece value;
      uint8_t* buf = reinterpret_cast<uint8_t *>(c.arena()->AllocateBytes(ilen));
      value.set(reinterpret_cast<char *>(buf), ilen);      
      buf += csqlitePutVarint(buf, i+1);
      // make kv pair
      std::pair<base::StringPiece, base::StringPiece> kv = std::make_pair(base::StringPiece(keyspaces[i]), value);
      // insert
      LOG(INFO) << "inserting keyspace '" << keyspaces[i] << "' = " << i+1;
      bool r = c.Insert(kv);
      if (!r) {
        LOG(ERROR) << "Database::CreateTables: fatal, error while writing keyspaces";
        tr2->Rollback();
        return false;
      } else {
        keyspaces_.emplace(std::make_pair(keyspaces[i], i+1));
      }
    }

    tr2->Commit();

  }
  
  return true;
}

bool Database::Init() {
  ExecuteStatement("PRAGMA journal_mode=WAL");
  ExecuteStatement("PRAGMA synchronous = FULL"); 
  ExecuteStatement("PRAGMA wal_autocheckpoint=4096");
  ExecuteStatement("PRAGMA schema.wal_checkpoint");
  ExecuteStatement("PRAGMA locking_mode=EXCLUSIVE");

  csqlite_extended_result_codes(sqlite_, 1);
  auto trans = BeginTransaction(false);
  if (!trans) {
    LOG(ERROR) << "Database::CreateTables: fatal, create read btree transaction failed";
    return false;
  }
  csqliteBtreeGetMeta(btree_, BTREE_LARGEST_ROOT_PAGE, &largest_root_page_);

  // the database got corrupted: TODO: how can we fix it?
  if (largest_root_page_ == 0) {
    DLOG(INFO) << "the dababase had a unclean shutdown and its corrupted. we need to recover it";
    //largest_root_page_ = 2;
  }
  
  DLOG(INFO) << ": init tables. table count: " << table_count_ << " largest_root_page: " << largest_root_page_;
  
  //if (largest_root_page_ == 0) {
  //  largest_root_page_ = 2;
  //}

  //if (table_count_ > 1) {
  
  // recover at least the keyspaces table
  tables_[0] = largest_root_page_;

  DLOG(INFO) << ": table table[0]: " << tables_[0];
  //} else {
    //pgnoRoot = 2;
  //  tables_[0] = largest_root_page_;
    //DLOG(INFO) << "apenas 1 table table[0]: " << tables_[0];
  //}

  //DLOG(INFO) << "retrieved pgnoRoot da table[0]: " << tables_[0];

  trans->Commit();

  // now lets get the keyspaces on table[0] 
  auto tr2 = BeginTransaction(false);
  if (!tr2) {
    return false;
  }
  size_t offset = 1;
  Cursor c(this, tr2.get(), "", 0);
  c.First();
  while (c.IsValid()) {
    bool valid = false;
    base::StringPiece payload = c.GetData();
    if (!payload.data()) {
      DLOG(ERROR) << "failed getting metadata row " << offset << ". Payload is empty";
      offset++;
      c.Next();
      continue;
    }
    KeyValuePair kv = DbDecodeKV(payload, &valid);
    if (!valid) {
      DLOG(ERROR) << "failed to decode KV pair";
      c.Next();
      offset++;
      continue;
    }
    std::string keyspace = kv.first.as_string();
    uint8_t const* buf = reinterpret_cast<uint8_t const*>(kv.second.begin());
    uint64_t index;
    csqliteGetVarint(buf, (u64*)&index);
    LOG(INFO) << "retrieved keyspace '" << keyspace << "' = " << index;
    keyspaces_.emplace(std::make_pair(std::move(keyspace), (int) index));
    table_count_++;
    c.Next();
    offset++;
  }

  tr2->Commit();

  // now init the tables recovered
  for (size_t i = table_count_; i != 0; i--) {
    tables_[i] = largest_root_page_ + i;
  }

  //csqlite_mutex_enter(sqlite_->mutex);
  
  return true; 
}

void Database::Close() {
  csqlite_close(sqlite_);
  //csqlite_mutex_leave(sqlite_->mutex);
  closed_ = true;
}

std::unique_ptr<Transaction> Database::BeginTransaction(bool write) {
  int id;
  int rc = csqliteBtreeBeginTrans(btree_, write ? 1 : 0, &id);
  //DCHECK(rc == SQLITE_OK) << " rc = " << rc;
  if (rc != SQLITE_OK) {
    DLOG(INFO) << "sqliteBtreeBeginTrans = " << rc;
    return nullptr;
  }
  return std::make_unique<Transaction>(this, write);
}

std::unique_ptr<Cursor> Database::CreateCursor(Transaction* tr, const std::string& keyspace) {
  int table = -1;
  if (!GetIndex(keyspace, &table)) {
    return {};
  }
  return std::make_unique<Cursor>(this, tr, keyspace, table);
}

bool Database::Get(Transaction* tr, const std::string& keyspace, base::StringPiece key, std::string* value) {
  auto cursor = CreateCursor(tr, keyspace);
  if (!cursor) {
    return false;
  }
  base::StringPiece tmp_value;
  bool r = cursor->GetValue(key, &tmp_value);
  if (r) {
    // we do a copy before commit, since the value
    // will vanish after that (the sqlite mapped mem page 
    // that the stringpiece is pointing to will go away)
    value->assign(tmp_value.data(), tmp_value.size());
  }
  return r;
}

bool Database::Put(Transaction* tr, const std::string& keyspace, base::StringPiece key, base::StringPiece value) {
  auto kv = std::make_pair(key, value);
  auto cursor = CreateCursor(tr, keyspace);
  if (!cursor) {
    return false;
  }
  bool r = cursor->Insert(kv);
  return r;
}

bool Database::Delete(Transaction* tr, const std::string& keyspace, base::StringPiece key) {
  bool r = false;
  bool match = false;

  auto cursor = CreateCursor(tr, keyspace);
  if (!cursor) {
    return false;
  }
  int rc = cursor->SeekTo(key, Seek::EQ, &match);
  if (rc != 0) {
    return false;
  }

  if (match) {
    r = cursor->Delete();
  }
  return r; 
}

bool Database::EraseAll(Transaction* tr) {
  return false;
}

bool Database::Check() {
  return false;
}

int Database::Count(Transaction* tr, const std::string& keyspace) {
  int table = -1;
  if (!GetIndex(keyspace, &table)) {
    return -1;
  }
  Cursor cursor(this, tr, keyspace, table);
  int count = cursor.Count();
  //if (autocommit) {
    //tr->Commit();
  //}
  return count;
}

bool Database::ExecuteStatement(const std::string& stmt) {
  csqlite_stmt* stmt_ptr = nullptr;
  csqlite_prepare_v2(sqlite_, stmt.c_str(), -1, &stmt_ptr, nullptr);
  int r = csqlite_step(stmt_ptr);
  csqlite_finalize(stmt_ptr);
  return r == SQLITE_ROW || r == SQLITE_DONE;
}

void DbInit() {
  csqlite_initialize();
}

void DbShutdown() {
  csqlite_shutdown();
}

KeyValuePair DbDecodeKV(base::StringPiece encoded, bool* valid) {
  uint8_t const* d = reinterpret_cast<uint8_t const*>(encoded.begin());
  uint64_t h, len1, len2;
  d += csqliteGetVarint(d, (u64*)&h);
  d += csqliteGetVarint(d, (u64*)&len1);
  d += csqliteGetVarint(d, (u64*)&len2);
  //DCHECK(d == reinterpret_cast<uint8_t const*>(&encoded.begin()[0]) + h );
  if (d != reinterpret_cast<uint8_t const*>(encoded.begin()) + h ) {
    DLOG(ERROR) << "bad payload: h = " << h << " - " << d << " != " << (encoded.begin() + h);
    *valid = false;
    return KeyValuePair();
  }

  if (len1 < 12 || (len1&1) ) {
    DLOG(ERROR) << "bad payload: len1 = " << len1;
    *valid = false;
    return KeyValuePair();
  }

  if (len2 < 12 || (len2&1) ) {
    DLOG(ERROR) << "bad payload: len2 = " << len2;
    *valid = false;
    return KeyValuePair(); 
  }
  
  len1 = (len1-12)/2;
  len2 = (len2-12)/2;
 // DCHECK(d + len1 + len2 == reinterpret_cast<uint8_t const*>(&encoded.end()[0]));
  if (d + len1 + len2 != reinterpret_cast<uint8_t const*>(encoded.end())) {
    DLOG(ERROR) << "bad payload: d + len1 + len2 (" << d + len1 + len2 << ") != " << encoded.end();
    *valid = false;
    return KeyValuePair();
  }

  *valid = true;
  return std::make_pair(base::StringPiece(reinterpret_cast<const char *>(d), len1), base::StringPiece(reinterpret_cast<const char *>(d+len1), len2));
}


bool Database::GetIndex(const std::string& keyspace, int* index) {
  auto it = keyspaces_.find(keyspace);
  if (it == keyspaces_.end()) {
    return false;
  }
  *index = it->second;
  return true;
}

Database* Database::Open(scoped_refptr<Torrent> torrent) {
  int rc;
  csqlite* db;
  Btree* btree;

  disk_vfs.pAppData = torrent.get();
  
  DCHECK(csqlite_vfs_register(&disk_vfs, 1) == SQLITE_OK);

  std::string uuid_str = torrent->id().string();

  rc = csqlite_open_v2(
    uuid_str.c_str(),
    &db, 
    SQLITE_OPEN_READWRITE, 
    STORAGE_VFS_NAME);

  if (rc != SQLITE_OK) {
    LOG(ERROR) << "Database::Open (" << torrent->id().to_string() << "): csqlite_open_v2: " << rc;
    return {};
  }

  btree = db->aDb[0].pBt;
 
  std::unique_ptr<Database> handle = std::unique_ptr<Database>(new Database(torrent->id(), db, btree, 0));

  if (!handle->Init()) {
    LOG(ERROR) << "Database initialization failed";
    return {};
  }

  Database* db_ptr = handle.get();
  torrent->set_owned_db(std::move(handle));
  return db_ptr;
}

Database* Database::Create(scoped_refptr<Torrent> torrent, const std::vector<std::string>& keyspaces) {
  int rc;
  csqlite* db;
  Btree* btree;

  disk_vfs.pAppData = torrent.get();
    
  DCHECK(csqlite_vfs_register(&disk_vfs, 1) == SQLITE_OK);

  std::string uuid_str = torrent->id().string();

  rc = csqlite_open_v2(
    uuid_str.c_str(),
    &db, 
    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, 
    STORAGE_VFS_NAME);

  if (rc != SQLITE_OK) {
    LOG(ERROR) << "Database::Create (" << torrent->id().to_string() << "): csqlite_open_v2: " << rc;
    return {};
  }

  btree = db->aDb[0].pBt;

  std::unique_ptr<Database> handle = std::unique_ptr<Database>(new Database(torrent->id(), db, btree, keyspaces.size()));
  
  if (!handle->CreateTables(keyspaces)) {
    LOG(ERROR) << "CreateTables failed";
    return {};
  }

  Database* db_ptr = handle.get();

  torrent->set_owned_db(std::move(handle));

  return db_ptr;
}

bool Database::Checkpoint(int* result_code) {
  std::string uuid_str = id_.string();
  int number_of_wal_log_frames = -1;
  int number_of_wal_checkpoint_frames = -1;
  
  int rc = csqlite_wal_checkpoint_v2(
    sqlite_,
    nullptr,//uuid_str.c_str(),
    SQLITE_CHECKPOINT_FULL,
    &number_of_wal_log_frames,
    &number_of_wal_checkpoint_frames);
  
  DLOG(INFO) << "Database::CheckPoint: \n" << 
   (rc == SQLITE_OK ? " success: " : " failed: ") << 
   "\n wal log frames: " << number_of_wal_log_frames << 
   " wal checkpoint frames: " << number_of_wal_checkpoint_frames;

  *result_code = rc; 

  return rc == SQLITE_OK;
}

}