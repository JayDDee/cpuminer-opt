#if !defined(INTRLV_MMX_H__)
#define INTRLV_MMX_H__ 1

#if defined(__MMX__)

//////////////////////////////////////////////////////
//
//          MMX 64 bit vectors

#define mm64_put_32( s0, s1 ) \
  _mm_set_pi32( *((const uint32_t*)(s1)), *((const uint32_t*)(s0)) )

#define mm64_get_32( s, i0, i1 ) \
  _mm_set_pi32( ((const uint32_t*)(s))[i1], ((const uint32_t*)(s))[i0] )

// 1 MMX block, 8 bytes * 2 lanes
static inline void mm64_intrlv_2x32( void *d, const void *s0,
                                     const void *s1, int len )
{
  casti_m64( d, 0 ) = mm64_put_32( s0    , s1     );
  casti_m64( d, 1 ) = mm64_put_32( s0+  4, s1+  4 );
  casti_m64( d, 2 ) = mm64_put_32( s0+  8, s1+  8 );
  casti_m64( d, 3 ) = mm64_put_32( s0+ 12, s1+ 12 );
  casti_m64( d, 4 ) = mm64_put_32( s0+ 16, s1+ 16 );
  casti_m64( d, 5 ) = mm64_put_32( s0+ 20, s1+ 20 );
  casti_m64( d, 6 ) = mm64_put_32( s0+ 24, s1+ 24 );
  casti_m64( d, 7 ) = mm64_put_32( s0+ 28, s1+ 28 );

  if ( len <= 256 ) return;

  casti_m64( d, 8 ) = mm64_put_32( s0+ 32, s1+ 32 );
  casti_m64( d, 9 ) = mm64_put_32( s0+ 36, s1+ 36 );
  casti_m64( d,10 ) = mm64_put_32( s0+ 40, s1+ 40 );
  casti_m64( d,11 ) = mm64_put_32( s0+ 44, s1+ 44 );
  casti_m64( d,12 ) = mm64_put_32( s0+ 48, s1+ 48 );
  casti_m64( d,13 ) = mm64_put_32( s0+ 52, s1+ 52 );
  casti_m64( d,14 ) = mm64_put_32( s0+ 56, s1+ 56 );
  casti_m64( d,15 ) = mm64_put_32( s0+ 60, s1+ 60 );

  if ( len <= 512 ) return;

  casti_m64( d,16 ) = mm64_put_32( s0+ 64, s1+ 64 );
  casti_m64( d,17 ) = mm64_put_32( s0+ 68, s1+ 68 );
  casti_m64( d,18 ) = mm64_put_32( s0+ 72, s1+ 72 );
  casti_m64( d,19 ) = mm64_put_32( s0+ 76, s1+ 76 );

  if ( len <= 640 ) return;
  casti_m64( d,20 ) = mm64_put_32( s0+ 80, s1+ 80 );
  casti_m64( d,21 ) = mm64_put_32( s0+ 84, s1+ 84 );
  casti_m64( d,22 ) = mm64_put_32( s0+ 88, s1+ 88 );
  casti_m64( d,23 ) = mm64_put_32( s0+ 92, s1+ 92 );
  casti_m64( d,24 ) = mm64_put_32( s0+ 96, s1+ 96 );
  casti_m64( d,25 ) = mm64_put_32( s0+100, s1+100 );
  casti_m64( d,26 ) = mm64_put_32( s0+104, s1+104 );
  casti_m64( d,27 ) = mm64_put_32( s0+108, s1+108 );
  casti_m64( d,28 ) = mm64_put_32( s0+112, s1+112 );
  casti_m64( d,29 ) = mm64_put_32( s0+116, s1+116 );
  casti_m64( d,30 ) = mm64_put_32( s0+120, s1+120 );
  casti_m64( d,31 ) = mm64_put_32( s0+124, s1+124 );
}

static inline void mm64_dintrlv_2x32( void *d00, void *d01, const int n,
                                      const void *s, int len )
{
   casti_m64( d00,0 ) = mm64_get_32( s,  0,  2 );
   casti_m64( d01,0 ) = mm64_get_32( s,  1,  3 );
   casti_m64( d00,1 ) = mm64_get_32( s,  4,  6 );
   casti_m64( d01,1 ) = mm64_get_32( s,  5,  7 );
   casti_m64( d00,2 ) = mm64_get_32( s,  8, 10 );
   casti_m64( d01,2 ) = mm64_get_32( s,  9, 11 );
   casti_m64( d00,3 ) = mm64_get_32( s, 12, 14 );
   casti_m64( d01,3 ) = mm64_get_32( s, 13, 15 );

   if ( len <= 256 ) return;

   casti_m64( d00,4 ) = mm64_get_32( s, 16, 18 );
   casti_m64( d01,4 ) = mm64_get_32( s, 17, 19 );
   casti_m64( d00,5 ) = mm64_get_32( s, 20, 22 );
   casti_m64( d01,5 ) = mm64_get_32( s, 21, 23 );
   casti_m64( d00,6 ) = mm64_get_32( s, 24, 26 );
   casti_m64( d01,6 ) = mm64_get_32( s, 25, 27 );
   casti_m64( d00,7 ) = mm64_get_32( s, 28, 30 );
   casti_m64( d01,7 ) = mm64_get_32( s, 29, 31 );

   if ( len <= 512 ) return;

   casti_m64( d00,8 ) = mm64_get_32( s, 32, 34 );
   casti_m64( d01,8 ) = mm64_get_32( s, 33, 35 );
   casti_m64( d00,9 ) = mm64_get_32( s, 36, 38 );
   casti_m64( d01,9 ) = mm64_get_32( s, 37, 39 );

   if ( len <= 640 ) return;
   casti_m64( d00,10 ) = mm64_get_32( s, 40, 42 );
   casti_m64( d01,10 ) = mm64_get_32( s, 41, 43 );
   casti_m64( d00,11 ) = mm64_get_32( s, 44, 46 );
   casti_m64( d01,11 ) = mm64_get_32( s, 45, 47 );
   casti_m64( d00,12 ) = mm64_get_32( s, 48, 50 );
   casti_m64( d01,12 ) = mm64_get_32( s, 49, 51 );
   casti_m64( d00,13 ) = mm64_get_32( s, 52, 54 );
   casti_m64( d01,13 ) = mm64_get_32( s, 53, 55 );
   casti_m64( d00,14 ) = mm64_get_32( s, 56, 58 );
   casti_m64( d01,14 ) = mm64_get_32( s, 57, 59 );
   casti_m64( d00,15 ) = mm64_get_32( s, 60, 62 );
   casti_m64( d01,15 ) = mm64_get_32( s, 61, 63 );
}

static inline void mm64_extr_lane_2x32( void *d, const void *s,
                                         const int lane, const int bit_len )
{
  casti_m64( d, 0 ) = mm64_get_32( s, lane   , lane+ 4 );
  casti_m64( d, 1 ) = mm64_get_32( s, lane+ 8, lane+12 );
  casti_m64( d, 2 ) = mm64_get_32( s, lane+16, lane+20 );
  casti_m64( d, 3 ) = mm64_get_32( s, lane+24, lane+28 );

  if ( bit_len <= 256 ) return;
  casti_m64( d, 4 ) = mm64_get_32( s, lane+32, lane+36 );
  casti_m64( d, 5 ) = mm64_get_32( s, lane+40, lane+44 );
  casti_m64( d, 6 ) = mm64_get_32( s, lane+48, lane+52 );
  casti_m64( d, 7 ) = mm64_get_32( s, lane+56, lane+60 );
  // bit_len == 512
}



#endif // MMX
#endif // INTRLV_MMX_H__
