#ifndef __XPT_STRUCT_H__
#define __XPT_STRUCT_H__

#define PR_TRUE 1
#define PR_FALSE 0

typedef unsigned char PRUint8;
typedef unsigned short PRUint16;
typedef unsigned int PRUint32;
typedef int PRInt32;

#ifndef nsID_h__
/*
 *  * We can't include nsID.h, because it's full of C++ goop and we're not doing
 *   * C++ here, so we define our own minimal struct.  We protect against multiple
 *    * definitions of this struct, though, and use the same field naming.
 *     */
struct nsID {
    PRUint32 m0;
    PRUint16 m1;
    PRUint16 m2;
    PRUint8  m3[8];
};

typedef struct nsID nsID;
#endif

#define XPT_MAJOR_VERSION 0x01
#define XPT_MINOR_VERSION 0x02

#define XPT_ASSERT(_expr) ((void)0)

#ifdef _WIN32
#define XP_WIN32
#define XP_WIN
#else
#define XP_UNIX
#endif

#endif
