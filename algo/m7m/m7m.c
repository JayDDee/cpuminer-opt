#include "cpuminer-config.h"
#include "algo-gate-api.h"

#include <gmp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>
#include <math.h>
#include "algo/keccak/sph_keccak.h"
#include "algo/haval/sph-haval.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/ripemd/sph_ripemd.h"
#include "algo/sha/sph_sha2.h"
#include "algo/sha/sha256-hash.h"

#define EPSa DBL_EPSILON
#define EPS1 DBL_EPSILON
#define EPS2 3.0e-11

inline double exp_n( double xt )
{
    if ( xt < -700.0 )
        return 0;
    else if ( xt > 700.0 )
        return 1e200;
    else if ( xt > -0.8e-8 && xt < 0.8e-8 )
        return ( 1.0 + xt );
    else
        return exp( xt );
}

inline double exp_n2( double x1, double x2 )
{
    double p1 = -700., p2 = -37., p3 = -0.8e-8, p4 = 0.8e-8,
           p5 = 37., p6 = 700.;
    double xt = x1 - x2;
    if ( xt < p1+1.e-200 )
        return 1.;
    else if ( xt > p1 && xt < p2 + 1.e-200 )
        return ( 1. - exp(xt) );
    else if ( xt > p2 && xt < p3 + 1.e-200 )
        return ( 1. / ( 1. + exp(xt) ) );
    else if ( xt > p3 && xt < p4 )
        return ( 1. / (2. + xt) );
    else if ( xt > p4 - 1.e-200 && xt < p5 )
        return ( exp(-xt) / ( 1. + exp(-xt) ) );
    else if ( xt > p5 - 1.e-200 && xt < p6 )
        return ( exp(-xt) );
    else if ( xt > p6 - 1.e-200 )
        return 0.;
}

double swit2_( double wvnmb )
{
    return pow( ( 5.55243 * ( exp_n( -0.3 * wvnmb / 15.762 )
                - exp_n( -0.6 * wvnmb / 15.762 ) ) ) * wvnmb, 0.5 ) 
	        / 1034.66 * pow( sin( wvnmb / 65. ), 2. );
}

double GaussianQuad_N2( const double x1, const double x2 )
{
    double s = 0.0;
    double x[6], w[6];
    //gauleg(a2, b2, x, w);
    
    double z1, z, xm, xl, pp, p3, p2, p1;
    xm = 0.5 * ( x2 + x1 );
    xl = 0.5 * ( x2 - x1 );
    for( int i = 1; i <= 3; i++ )
    {
      z = (i == 2) ? 0.540641 : ( (i == 1) ? 0.909632 : -0.0 );
      do
	    {
			p1 = ( ( 3.0 * z * z ) - 1 ) / 2;
			p2 = p1;
         p1 = ( ( 5.0 * z * p2 ) - ( 2.0 * z ) ) / 3;
			p3 = p2;
			p2 = p1;
			p1 = ( ( 7.0 * z * p2 ) - ( 3.0 * p3 ) ) / 4;
			p3 = p2;
			p2 = p1;
			p1 = ( ( 9.0 * z * p2 ) - ( 4.0 * p3 ) ) / 5;
         pp = 5 * ( z * p1 - p2 ) / ( z * z - 1.0 );
		   z1 = z;
		   z = z1 - p1 / pp;
	    } while ( fabs( z - z1 ) > 3.0e-11 );
	    
	    x[i]       = xm - xl * z;
	    x[ 5+1-i ] = xm + xl * z;
	    w[i]       = 2.0 * xl / ( ( 1.0 - z * z ) * pp * pp );
	    w[ 5+1-i ] = w [i];
    }
    
    for( int j = 1; j <= 5; j++ ) s += w[j] * swit2_( x[j] );
    
    return s;
}

uint32_t sw2_( int nnounce )
{
    double wmax = ( ( sqrt( (double)(nnounce) ) * ( 1.+EPSa ) ) / 450+100 );
    return ( (uint32_t)( GaussianQuad_N2( 0., wmax ) * ( 1.+EPSa ) * 1.e6 ) );
}

typedef struct {
    sha256_context           sha256;
    sph_sha512_context       sha512;
    sph_keccak512_context    keccak;
    sph_whirlpool_context    whirlpool;
    sph_haval256_5_context   haval;
    sph_tiger_context        tiger;
    sph_ripemd160_context    ripemd;
} m7m_ctx_holder;

m7m_ctx_holder m7m_ctx;

void init_m7m_ctx()
{
    sha256_ctx_init( &m7m_ctx.sha256 );
    sph_sha512_init( &m7m_ctx.sha512 );
    sph_keccak512_init( &m7m_ctx.keccak );
    sph_whirlpool_init( &m7m_ctx.whirlpool );
    sph_haval256_5_init( &m7m_ctx.haval );
    sph_tiger_init( &m7m_ctx.tiger );
    sph_ripemd160_init( &m7m_ctx.ripemd );
}

#define BITS_PER_DIGIT 3.32192809488736234787
#define EPS (DBL_EPSILON)

#define NM7M 5
#define SW_DIVS 5
#define M7_MIDSTATE_LEN 76
int scanhash_m7m_hash( struct work* work, uint64_t max_nonce,
                       unsigned long *hashes_done, struct thr_info *mythr )
{
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t data[32] __attribute__((aligned(64)));
    uint32_t *data_p64 = data + (M7_MIDSTATE_LEN / sizeof(data[0]));
    uint32_t hash[8] __attribute__((aligned(64)));
    uint8_t bhash[7][64] __attribute__((aligned(64)));
    uint32_t n = pdata[19] - 1;
    int thr_id = mythr->id;
    uint32_t usw_, mpzscale;
    const uint32_t first_nonce = pdata[19];
    char data_str[161], hash_str[65], target_str[65];
    uint8_t bdata[8192] __attribute__ ((aligned (64)));
    int i, digits;
    int bytes;
    size_t p = sizeof(unsigned long), a = 64/p, b = 32/p;

    m7m_ctx_holder ctx1, ctx2 __attribute__ ((aligned (64)));
    memcpy( &ctx1, &m7m_ctx, sizeof(m7m_ctx) );

    memcpy(data, pdata, 80);

    sha256_update(  &ctx1.sha256,    data, M7_MIDSTATE_LEN );
    sph_sha512(     &ctx1.sha512,    data, M7_MIDSTATE_LEN );
    sph_keccak512(  &ctx1.keccak,    data, M7_MIDSTATE_LEN );
    sph_whirlpool(  &ctx1.whirlpool, data, M7_MIDSTATE_LEN );
    sph_haval256_5( &ctx1.haval,     data, M7_MIDSTATE_LEN );
    sph_tiger(      &ctx1.tiger,     data, M7_MIDSTATE_LEN );
    sph_ripemd160(  &ctx1.ripemd,    data, M7_MIDSTATE_LEN );

    mpz_t magipi, magisw, product, bns0, bns1;
    mpf_t magifpi, magifpi0, mpt1, mpt2, mptmp, mpten;
    
    mpz_inits(magipi, magisw, bns0, bns1, NULL);
    mpz_init2(product, 512);

    mp_bitcnt_t prec0 = (long int)((int)((sqrt((double)(INT_MAX))*(1.+EPS))/9000+75)*BITS_PER_DIGIT+16);
    mpf_set_default_prec(prec0);

    mpf_init(magifpi);
    mpf_init(magifpi0);
    mpf_init(mpt1);
    mpf_init(mpt2);
    mpf_init(mptmp);
    mpf_init_set_ui(mpten, 10);
    mpf_set_str(mpt2, "0.8e3b1a9b359805c2e54c6415037f2e336893b6457f7754f6b4ae045eb6c5f2bedb26a114030846be7", 16);
    mpf_set_str(magifpi0, "0.b7bfc6837e20bdb22653f1fc419f6bc33ca80eb65b7b0246f7f3b65689560aea1a2f2fd95f254d68c", 16);

    do {
        data[19] = ++n;
        memset(bhash, 0, 7 * 64);

        memcpy( &ctx2, &ctx1, sizeof(m7m_ctx) );

        sha256_update( &ctx2.sha256, data_p64, 80 - M7_MIDSTATE_LEN );
        sha256_final( &ctx2.sha256, bhash[0] );

        sph_sha512(  &ctx2.sha512, data_p64, 80 - M7_MIDSTATE_LEN );
        sph_sha512_close( &ctx2.sha512, bhash[1] );

        sph_keccak512( &ctx2.keccak, data_p64, 80 - M7_MIDSTATE_LEN );
        sph_keccak512_close( &ctx2.keccak, (void*)(bhash[2]) );

        sph_whirlpool( &ctx2.whirlpool, data_p64, 80 - M7_MIDSTATE_LEN );
        sph_whirlpool_close( &ctx2.whirlpool, (void*)(bhash[3]) );

        sph_haval256_5( &ctx2.haval, data_p64, 80 - M7_MIDSTATE_LEN );
        sph_haval256_5_close( &ctx2.haval, (void*)(bhash[4])) ;

        sph_tiger( &ctx2.tiger, data_p64, 80 - M7_MIDSTATE_LEN );
        sph_tiger_close( &ctx2.tiger, (void*)(bhash[5]) );

        sph_ripemd160( &ctx2.ripemd, data_p64, 80 - M7_MIDSTATE_LEN );
        sph_ripemd160_close( &ctx2.ripemd, (void*)(bhash[6]) );

        mpz_import(bns0, a, -1, p, -1, 0, bhash[0]);
        mpz_set(bns1, bns0);
	     mpz_set(product, bns0);
	     for ( i=1; i < 7; i++ )
        {
	        mpz_import(bns0, a, -1, p, -1, 0, bhash[i]);
	        mpz_add(bns1, bns1, bns0);
           mpz_mul(product, product, bns0);
        }
        mpz_mul(product, product, bns1);

        mpz_mul(product, product, product);
        bytes = mpz_sizeinbase(product, 256);
        mpz_export((void *)bdata, NULL, -1, 1, 0, 0, product);

        sha256_full( hash, bdata, bytes );

        digits=(int)((sqrt((double)(n/2))*(1.+EPS))/9000+75);
        mp_bitcnt_t prec = (long int)(digits*BITS_PER_DIGIT+16);
        mpf_set_prec_raw(magifpi, prec);
        mpf_set_prec_raw(mptmp, prec);
        mpf_set_prec_raw(mpt1, prec);
        mpf_set_prec_raw(mpt2, prec);

        usw_ = sw2_(n/2);
	     mpzscale = 1;
        mpz_set_ui(magisw, usw_);
	    
        for ( i = 0; i < 5; i++ )
        {	
            mpf_set_d(mpt1, 0.25*mpzscale);
	         mpf_sub(mpt1, mpt1, mpt2);
            mpf_abs(mpt1, mpt1);
            mpf_div(magifpi, magifpi0, mpt1);
            mpf_pow_ui(mptmp, mpten, digits >> 1);
            mpf_mul(magifpi, magifpi, mptmp);
	         mpz_set_f(magipi, magifpi);
            mpz_add(magipi,magipi,magisw);
            mpz_add(product,product,magipi);
	         mpz_import(bns0, b, -1, p, -1, 0, (void*)(hash));
            mpz_add(bns1, bns1, bns0);
            mpz_mul(product,product,bns1);
            mpz_cdiv_q (product, product, bns0);

            bytes = mpz_sizeinbase(product, 256);
            mpzscale=bytes;
            mpz_export(bdata, NULL, -1, 1, 0, 0, product);

            sha256_full( hash, bdata, bytes );
	     }

        if ( unlikely( valid_hash( (uint64_t*)hash, (uint64_t*)ptarget ) 
             && !opt_benchmark ) )
        {
           if ( opt_debug )
           {
                bin2hex( hash_str, (unsigned char *)hash, 32 );
                bin2hex( target_str, (unsigned char *)ptarget, 32 );
                bin2hex( data_str, (unsigned char *)data, 80 );
                applog( LOG_DEBUG, "DEBUG: [%d thread] Found share!\ndata   %s\nhash   %s\ntarget %s",
                      thr_id, data_str, hash_str, target_str );
            }
            pdata[19] = data[19];
            submit_solution( work, hash, mythr );
        }
    } while ( n < max_nonce && !work_restart[thr_id].restart );

     pdata[19] = n;

     mpf_set_prec_raw( magifpi, prec0 );
     mpf_set_prec_raw( magifpi0, prec0 );
     mpf_set_prec_raw( mptmp, prec0 );
     mpf_set_prec_raw( mpt1, prec0 );
     mpf_set_prec_raw( mpt2, prec0 );
     mpf_clear( magifpi );
     mpf_clear( magifpi0 );
     mpf_clear( mpten );
     mpf_clear( mptmp );
     mpf_clear( mpt1 );
     mpf_clear( mpt2 );
     mpz_clears( magipi, magisw, product, bns0, bns1, NULL );

    *hashes_done = n - first_nonce + 1;
    return 0;
}

bool register_m7m_algo( algo_gate_t *gate )
{
  gate->optimizations = SHA_OPT;
  init_m7m_ctx();
  gate->scanhash              = (void*)&scanhash_m7m_hash;
  gate->build_stratum_request = (void*)&std_be_build_stratum_request;
  gate->work_decode           = (void*)&std_be_work_decode;
  gate->submit_getwork_result = (void*)&std_be_submit_getwork_result;
  gate->set_work_data_endian  = (void*)&set_work_data_big_endian;
  opt_target_factor = 65536.0;
  return true;
}


