// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_FRAMER_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_FRAMER_PEER_H_

#include "base/macros.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/quic_framer.h"
#include "net/quic/core/quic_packets.h"

namespace net {

namespace test {

class QuicFramerPeer {
 public:
  static QuicPacketNumber CalculatePacketNumberFromWire(
      QuicFramer* framer,
      QuicPacketNumberLength packet_number_length,
      QuicPacketNumber last_packet_number,
      QuicPacketNumber packet_number);
  static void SetLastSerializedConnectionId(QuicFramer* framer,
                                            QuicConnectionId connection_id);
  static void SetLargestPacketNumber(QuicFramer* framer,
                                     QuicPacketNumber packet_number);
  static void SetPerspective(QuicFramer* framer, Perspective perspective);

  // SwapCrypters exchanges the state of the crypters of |framer1| with
  // |framer2|.
  static void SwapCrypters(QuicFramer* framer1, QuicFramer* framer2);

  static QuicEncrypter* GetEncrypter(QuicFramer* framer, EncryptionLevel level);

  static void SetLastPacketIsIetfQuic(QuicFramer* framer,
                                      bool last_packet_is_ietf_quic);

  // IETF defined frame append/process methods.
  static bool ProcessIetfStreamFrame(QuicFramer* framer,
                                     QuicDataReader* reader,
                                     uint8_t frame_type,
                                     QuicStreamFrame* frame);
  static bool AppendIetfStreamFrame(QuicFramer* framer,
                                    const QuicStreamFrame& frame,
                                    bool last_frame_in_packet,
                                    QuicDataWriter* writer);

  static bool AppendIetfConnectionCloseFrame(
      QuicFramer* framer,
      const QuicConnectionCloseFrame& frame,
      QuicDataWriter* writer);
  static bool AppendIetfApplicationCloseFrame(
      QuicFramer* framer,
      const QuicConnectionCloseFrame& frame,
      QuicDataWriter* writer);
  static bool ProcessIetfConnectionCloseFrame(QuicFramer* framer,
                                              QuicDataReader* reader,
                                              const uint8_t frame_type,
                                              QuicConnectionCloseFrame* frame);
  static bool ProcessIetfApplicationCloseFrame(QuicFramer* framer,
                                               QuicDataReader* reader,
                                               const uint8_t frame_type,
                                               QuicConnectionCloseFrame* frame);
  static bool ProcessIetfAckFrame(QuicFramer* framer,
                                  QuicDataReader* reader,
                                  uint8_t frame_type,
                                  QuicAckFrame* ack_frame);
  static bool AppendIetfAckFrame(QuicFramer* framer,
                                 const QuicAckFrame& frame,
                                 QuicDataWriter* writer);
  static bool AppendIetfResetStreamFrame(QuicFramer* framer,
                                         const QuicRstStreamFrame& frame,
                                         QuicDataWriter* writer);
  static bool ProcessIetfResetStreamFrame(QuicFramer* framer,
                                          QuicDataReader* reader,
                                          QuicRstStreamFrame* frame);

  // Add/remove IETF-Format padding.
  static bool AppendIetfPaddingFrame(QuicFramer* framer,
                                     const QuicPaddingFrame& frame,
                                     QuicDataWriter* writer);
  static void ProcessIetfPaddingFrame(QuicFramer* framer,
                                      QuicDataReader* reader,
                                      QuicPaddingFrame* frame);

  static bool ProcessIetfPathChallengeFrame(QuicFramer* framer,
                                            QuicDataReader* reader,
                                            QuicPathChallengeFrame* frame);
  static bool ProcessIetfPathResponseFrame(QuicFramer* framer,
                                           QuicDataReader* reader,
                                           QuicPathResponseFrame* frame);

  static bool AppendIetfPathChallengeFrame(QuicFramer* framer,
                                           const QuicPathChallengeFrame& frame,
                                           QuicDataWriter* writer);
  static bool AppendIetfPathResponseFrame(QuicFramer* framer,
                                          const QuicPathResponseFrame& frame,
                                          QuicDataWriter* writer);

  static bool ProcessIetfStopSendingFrame(
      QuicFramer* framer,
      QuicDataReader* reader,
      QuicStopSendingFrame* stop_sending_frame);
  static bool AppendIetfStopSendingFrame(
      QuicFramer* framer,
      const QuicStopSendingFrame& stop_sending_frame,
      QuicDataWriter* writer);

  // Append/consume IETF-Format MAX_DATA and MAX_STREAM_DATA frames
  static bool AppendIetfMaxDataFrame(QuicFramer* framer,
                                     const QuicWindowUpdateFrame& frame,
                                     QuicDataWriter* writer);
  static bool AppendIetfMaxStreamDataFrame(QuicFramer* framer,
                                           const QuicWindowUpdateFrame& frame,
                                           QuicDataWriter* writer);
  static bool ProcessIetfMaxDataFrame(QuicFramer* framer,
                                      QuicDataReader* reader,
                                      QuicWindowUpdateFrame* frame);
  static bool ProcessIetfMaxStreamDataFrame(QuicFramer* framer,
                                            QuicDataReader* reader,
                                            QuicWindowUpdateFrame* frame);
  static bool AppendIetfMaxStreamIdFrame(QuicFramer* framer,
                                         const QuicIetfMaxStreamIdFrame& frame,
                                         QuicDataWriter* writer);
  static bool ProcessIetfMaxStreamIdFrame(QuicFramer* framer,
                                          QuicDataReader* reader,
                                          QuicIetfMaxStreamIdFrame* frame);
  static bool AppendIetfBlockedFrame(QuicFramer* framer,
                                     const QuicIetfBlockedFrame& frame,
                                     QuicDataWriter* writer);
  static bool ProcessIetfBlockedFrame(QuicFramer* framer,
                                      QuicDataReader* reader,
                                      QuicIetfBlockedFrame* frame);

  static bool AppendIetfStreamBlockedFrame(QuicFramer* framer,
                                           const QuicWindowUpdateFrame& frame,
                                           QuicDataWriter* writer);
  static bool ProcessIetfStreamBlockedFrame(QuicFramer* framer,
                                            QuicDataReader* reader,
                                            QuicWindowUpdateFrame* frame);

  static bool AppendIetfStreamIdBlockedFrame(
      QuicFramer* framer,
      const QuicIetfStreamIdBlockedFrame& frame,
      QuicDataWriter* writer);
  static bool ProcessIetfStreamIdBlockedFrame(
      QuicFramer* framer,
      QuicDataReader* reader,
      QuicIetfStreamIdBlockedFrame* frame);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicFramerPeer);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_FRAMER_PEER_H_
