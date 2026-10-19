/* `make check` driver for the RandomX known-answer tests.
 *
 * Thin on purpose: the vectors and the checks live in randomx-kat.c, which is
 * also compiled into cpuminer so the algo gate can run the quick subset at
 * startup. Keeping main() in its own file avoids compiling randomx-kat.c twice
 * with different macros -- which is the kind of arrangement that ends up
 * testing a different build from the one that ships.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

int  rx_kat_full( int full );
int  rx_kat_bench( int nonces );
int  rx_kat_sweep( int nonces, int maxthreads );
bool rx_kat_selftest( void );

int main( int argc, char **argv )
{
   int full = 0, selftest_only = 0, bench = 0, i;
   int sweep_thr = 0, sweep_n = 250;

   for ( i = 1; i < argc; i++ )
   {
      if ( !strcmp( argv[i], "--full" ) )
         full = 1;
      else if ( !strcmp( argv[i], "--selftest" ) )
         selftest_only = 1;
      else if ( !strcmp( argv[i], "--bench" ) )
         bench = ( i + 1 < argc ) ? atoi( argv[++i] ) : 64;
      else if ( !strcmp( argv[i], "--sweep" ) )
      {
         sweep_thr = ( i + 1 < argc ) ? atoi( argv[++i] ) : 8;
         if ( i + 1 < argc && argv[i+1][0] != '-' )
            sweep_n = atoi( argv[++i] );
      }
      else
      {
         fprintf( stderr, "usage: %s [--full] [--selftest] [--bench N] "
                          "[--sweep MAXTHREADS [NONCES]]\n", argv[0] );
         return 2;
      }
   }

   if ( sweep_thr )
      return rx_kat_sweep( sweep_n, sweep_thr );

   if ( bench )
      return rx_kat_bench( bench );

   if ( selftest_only )
   {
      bool ok = rx_kat_selftest();
      printf( "RANDOMX SELFTEST: %s\n", ok ? "PASS" : "FAIL" );
      return ok ? 0 : 1;
   }

   return rx_kat_full( full );
}
