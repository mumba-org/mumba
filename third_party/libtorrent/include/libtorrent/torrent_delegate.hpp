#ifndef TORRENT_TORRENT_DELEGATE_HPP_INCLUDE
#define TORRENT_TORRENT_DELEGATE_HPP_INCLUDE

#include "libtorrent/torrent_handle.hpp"
#include "libtorrent/torrent_status.hpp"
#include "libtorrent/aux_/storage_utils.hpp" // for iovec_t

namespace libtorrent {

class TorrentStorageDelegate {
public:
  virtual ~TorrentStorageDelegate() {}
  virtual bool OpenEntry(storage_index_t storage) = 0;
  virtual bool CreateEntry(storage_index_t storage) = 0;
  virtual void ReadEntry(lt::storage_index_t storage, span<iovec_t const> bufs, piece_index_t const piece, int const offset, storage_error& error) = 0;
  virtual void WriteEntry(lt::storage_index_t storage, lt::span<lt::iovec_t const> bufs, lt::piece_index_t const piece, int const offset, lt::storage_error& error) = 0;
  virtual const char* GetEntryHash(storage_index_t storage, piece_index_t piece) = 0;
  virtual std::vector<const char *> GetEntryBlockHashes(lt::storage_index_t storage) = 0;
  virtual void UpdateMerkleTree(lt::storage_index_t storage, const std::vector<const char *>& block_hashes) = 0;
  virtual bool EntryChecked(lt::storage_index_t storage) = 0;
  virtual void SetEntryChecked(lt::storage_index_t storage, bool checked) = 0;
  virtual void OnReleaseFiles(lt::storage_index_t storage) = 0;
};

class TorrentDelegate {
public:
  virtual ~TorrentDelegate() {}
  virtual void OnTorrentChecked(torrent_handle handle) = 0;
  virtual void OnTorrentPaused(torrent_handle handle) = 0;
  //virtual void OnTorrentFinished(torrent_handle handle) = 0;
  virtual void OnTorrentResumed(torrent_handle handle) = 0;
  virtual void OnTorrentDeleted(torrent_handle handle, sha1_hash const& ih) = 0;
  virtual void OnTorrentDeletedError(torrent_handle handle, 
                                     error_code const& ec, 
                                     sha1_hash const& ih) = 0;
  virtual void OnTorrentFileRenamed(torrent_handle handle, 
                                    string_view name, 
                                    file_index_t index) = 0;

  virtual void OnTorrentStateChanged(torrent_handle const& h, 
                                     torrent_status::state_t st, 
                                     torrent_status::state_t prev_st) = 0;

  virtual void OnTorrentFileRenamedError(torrent_handle handle, 
                                         file_index_t index, 
                                         error_code const& ec) = 0;

  virtual void OnDHTAnnounceReply(torrent_handle handle, int peers) = 0;
  virtual void OnBlockFinished(torrent_handle h, 
                               tcp::endpoint const& ep, 
                               peer_id const& peer_id, 
                               int block_num, 
                               piece_index_t piece_num) = 0;
  virtual void OnPieceReadError(torrent_handle const& handle, 
                                piece_index_t piece_num,
                                error_code const& ec) = 0;
  virtual void OnPieceFinished(torrent_handle const& handle, 
                               piece_index_t piece_num) = 0;
  virtual void OnPieceHashedError(error_code const& ec, 
                                  string_view file, 
                                  operation_t op, 
                                  torrent_handle const& h) = 0;
  virtual void OnTrackerWarning(torrent_handle const& handle, 
                                tcp::endpoint const& endpoint, 
                                string_view url, 
                                string_view message) = 0;
  virtual void OnTrackerScrapeReply(torrent_handle const& handle, 
                                    tcp::endpoint const& endpoint,
                                    int incomplete, 
                                    int complete, 
                                    string_view url) = 0;
  virtual void OnTrackerScrapeError(torrent_handle const& h, 
                                    tcp::endpoint const& ep, 
                                    string_view u, 
                                    error_code const& e) = 0;
  virtual void OnTrackerReply(torrent_handle const& handle, 
                              tcp::endpoint const& endpoint, 
                              int num_peers, 
                              string_view url) = 0;
  virtual void OnTrackerRequestError(torrent_handle const& handle,
                                     tcp::endpoint const& ep, 
                                     int times,
                                     string_view url, 
                                     error_code const& err, 
                                     string_view message) = 0;
  virtual void OnMetadataReceived(torrent_handle const& handle) = 0;
  
  virtual void OnMetadataError(torrent_handle const& handle, error_code const& ec) = 0;

  virtual void OnPeerBlocked(torrent_handle const& handle, 
                             tcp::endpoint const& endpoint, 
                             int result) = 0;
  virtual void OnFileCompleted(torrent_handle const& handle, file_index_t idx) = 0;
  
  virtual void OnPieceHashCheckFailed(torrent_handle const& handle, piece_index_t piece_num) = 0;

  virtual void OnPiecePass(torrent_handle const& handle, 
                           piece_index_t piece_num) = 0;

  virtual void OnPieceFailed(torrent_handle const& handle, 
                             piece_index_t piece_num) = 0;
};

}

#endif