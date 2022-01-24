#include "libavformat/avformat.h"

int main() {
  AVCodec *codec;
  AVPacket avpkt;

  av_init_packet(&avpkt);
  codec = avcodec_find_decoder(AV_CODEC_ID_MP2);
  if (!codec) {
    fprintf(stderr, "Codec not found\n");
    exit(1);
  }
  return 0;
}
