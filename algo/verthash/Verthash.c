/*
 * Copyright 2018-2021 CryptoGraphics
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version. See LICENSE for more details.
 */

#include "algo-gate-api.h"
#include "Verthash.h"
#include "mm_malloc.h"

//-----------------------------------------------------------------------------
// Verthash info management
int verthash_info_init(verthash_info_t* info, const char* file_name)
{
    // init fields to 0
    info->fileName = NULL;
    info->data = NULL;
    info->dataSize = 0;
    info->bitmask = 0;
    size_t fileNameLen;

    if ( !file_name || !( fileNameLen = strlen( file_name ) ) ) 
    { 
       applog( LOG_ERR, "Invalid file specification" );
       return -1; 
    }
    
    info->fileName = (char*)malloc( fileNameLen + 1 );
    if ( !info->fileName )
    {
        applog( LOG_ERR, "Failed to allocate memory for Verthash data" );
        return -1;
    }

    memset( info->fileName, 0, fileNameLen + 1 );
    memcpy( info->fileName, file_name, fileNameLen );

    FILE *fileMiningData = fopen_utf8( info->fileName, "rb" );
    if ( !fileMiningData )
    {
       if ( opt_data_file || !opt_verify ) 
       {
          if ( opt_data_file )
             applog( LOG_ERR, "Verthash data file not found or invalid: %s",
                     info->fileName );
          else
          {
             applog( LOG_ERR,
                     "No Verthash data file specified and default not found");
             applog( LOG_NOTICE,
                     "Add '--verify' to create default 'verthash.dat'");
          }
          return -1;
       }
       else
       {
          applog( LOG_NOTICE, "Creating default 'verthash.dat' in current directory, this will take several minutes");
          if ( verthash_generate_data_file( info->fileName ) )
             return -1;

          fileMiningData = fopen_utf8( info->fileName, "rb" );
          if ( !fileMiningData )
          {
              applog( LOG_ERR, "File system error opening %s", info->fileName );
              return -1;
          }

          applog( LOG_NOTICE, "Verthash data file created successfully" );
       }
    }

    // Get file size
    fseek(fileMiningData, 0, SEEK_END);
    int fileSize = ftell(fileMiningData);
    fseek(fileMiningData, 0, SEEK_SET);

    if ( fileSize < 0 ) 
    {
        fclose(fileMiningData);
        return 1;
    }

    // Allocate data
    info->data = (uint8_t *)_mm_malloc( fileSize, 64 );
    if (!info->data)
    {
        fclose(fileMiningData);
        // Memory allocation fatal error.
        return 2;
    }

    // Load data
    if ( !fread( info->data, fileSize, 1, fileMiningData ) )
    {
        applog( LOG_ERR, "File system error reading %s", info->fileName );
        fclose(fileMiningData);
        return -1;
    }

    fclose(fileMiningData);

    // Update fields
    info->bitmask = ((fileSize - VH_HASH_OUT_SIZE)/VH_BYTE_ALIGNMENT) + 1;
    info->dataSize = fileSize;

    applog( LOG_NOTICE, "Using Verthash data file '%s'", info->fileName );
    return 0;
}

//-----------------------------------------------------------------------------
void verthash_info_free(verthash_info_t* info)
{
    free(info->fileName);
    free(info->data);
    info->dataSize = 0;
    info->bitmask = 0;
}


//-----------------------------------------------------------------------------
// Verthash hash
#define VH_P0_SIZE 64
#define VH_N_ITER 8 
#define VH_N_SUBSET VH_P0_SIZE*VH_N_ITER
#define VH_N_ROT 32
#define VH_N_INDEXES 4096
#define VH_BYTE_ALIGNMENT 16

static inline uint32_t fnv1a(const uint32_t a, const uint32_t b)
{
    return (a ^ b) * 0x1000193;
}

#if 0
static void rotate_indexes( uint32_t *p )
{
#if defined(__AVX2__)

   for ( size_t x = 0; x < VH_N_SUBSET / sizeof(__m256i); x += 8 )
   {
      __m256i *px = (__m256i*)p + x;

      px[0] = mm256_rol_32( px[0], 1 );
      px[1] = mm256_rol_32( px[1], 1 );
      px[2] = mm256_rol_32( px[2], 1 );
      px[3] = mm256_rol_32( px[3], 1 );
      px[4] = mm256_rol_32( px[4], 1 );
      px[5] = mm256_rol_32( px[5], 1 );
      px[6] = mm256_rol_32( px[6], 1 );
      px[7] = mm256_rol_32( px[7], 1 );
   }

#else

   for ( size_t x = 0; x < VH_N_SUBSET / sizeof(__m128i); x += 8 )
   {
      __m128i *px = (__m128i*)p0_index + x;

      px[0] = mm128_rol_32( px[0], 1 );
      px[1] = mm128_rol_32( px[1], 1 );
      px[2] = mm128_rol_32( px[2], 1 );
      px[3] = mm128_rol_32( px[3], 1 );
      px[4] = mm128_rol_32( px[4], 1 );
      px[5] = mm128_rol_32( px[5], 1 );
      px[6] = mm128_rol_32( px[6], 1 );
      px[7] = mm128_rol_32( px[7], 1 );
   }

#endif
/*   
   for ( size_t x = 0; x < VH_N_SUBSET / sizeof(uint32_t); ++x )
      p[x] = ( p[x] << 1 ) | ( p[x] >> 31 );
*/
}
#endif
// Vectorized and targetted version of fnv1a
#if defined (__AVX2__)        

#define MULXOR \
   *(__m256i*)hash = _mm256_mullo_epi32( _mm256_xor_si256( \
                                 *(__m256i*)hash, *(__m256i*)blob_off ), k );

#elif defined(__SSE41__)

#define MULXOR \
   casti_m128i( hash, 0 ) = _mm_mullo_epi32( _mm_xor_si128( \
                  casti_m128i( hash, 0 ), casti_m128i( blob_off, 0 ) ), k ); \
   casti_m128i( hash, 1 ) = _mm_mullo_epi32( _mm_xor_si128( \
                  casti_m128i( hash, 1 ), casti_m128i( blob_off, 1 ) ), k );

#else

#define MULXOR \
   for ( size_t j = 0; j < VH_HASH_OUT_SIZE / sizeof(uint32_t); j++ ) \
       hash[j] = fnv1a( hash[j], blob_off[j] ); \

#endif

#define UPDATE_ACCUMULATOR \
   accumulator = fnv1a( accumulator, blob_off[0] ); \
   accumulator = fnv1a( accumulator, blob_off[1] ); \
   accumulator = fnv1a( accumulator, blob_off[2] ); \
   accumulator = fnv1a( accumulator, blob_off[3] ); \
   accumulator = fnv1a( accumulator, blob_off[4] ); \
   accumulator = fnv1a( accumulator, blob_off[5] ); \
   accumulator = fnv1a( accumulator, blob_off[6] ); \
   accumulator = fnv1a( accumulator, blob_off[7] )


// first pass no rotate
#define ROUND_0 \
for ( size_t i = 0; i < VH_N_SUBSET / sizeof(uint32_t); i++ ) \
{ \
   const uint32_t *blob_off = blob + \
                         ( ( fnv1a( subset[i], accumulator ) % mdiv ) \
                         * ( VH_BYTE_ALIGNMENT / sizeof(uint32_t) ) ); \
   UPDATE_ACCUMULATOR; \
   MULXOR; \
}

// subsequent passes rotate by r on demand, no need for mass rotate
#define ROUND_r( r ) \
for ( size_t i = 0; i < VH_N_SUBSET / sizeof(uint32_t); i++ ) \
{ \
   const uint32_t *blob_off = blob + \
                 ( ( fnv1a( rol32( subset[i], r ), accumulator ) % mdiv ) \
                 * ( VH_BYTE_ALIGNMENT / sizeof(uint32_t) ) ); \
   UPDATE_ACCUMULATOR; \
   MULXOR; \
}

void verthash_hash( const void *blob_bytes, const size_t blob_size,
                    const void *input, void *output )
{
    uint32_t hash[ VH_HASH_OUT_SIZE / 4 ] __attribute__ ((aligned (64)));
    uint32_t subset[ VH_N_SUBSET / 4 ] __attribute__ ((aligned (64)));
    const uint32_t *blob = (const uint32_t*)blob_bytes;
    uint32_t accumulator = 0x811c9dc5;
    const uint32_t mdiv = ( ( blob_size - VH_HASH_OUT_SIZE )
                             / VH_BYTE_ALIGNMENT ) + 1;
#if defined (__AVX2__)        
    const __m256i k = _mm256_set1_epi32( 0x1000193 );
#elif defined(__SSE41__)
    const __m128i k = _mm_set1_epi32( 0x1000193 );
#endif
    
    sha3( input, VH_HEADER_SIZE, hash, VH_HASH_OUT_SIZE );
    verthash_sha3_512_final_8( subset, ( (uint64_t*)input )[ 9 ] );

    ROUND_0;
    for ( size_t r = 1; r < VH_N_ROT; ++r )
       ROUND_r( r );

    memcpy( output, hash, VH_HASH_OUT_SIZE );
}

//-----------------------------------------------------------------------------
// Verthash data file generator

#define NODE_SIZE 32

struct Graph
{
    FILE *db;
    int64_t log2;
    int64_t pow2;
    uint8_t *pk;
    int64_t index;
};

int64_t Log2(int64_t x)
{
    int64_t r = 0;
    for (; x > 1; x >>= 1)
    {
        r++;
    }

    return r;
}

int64_t bfsToPost(struct Graph *g, const int64_t node)
{
    return node & ~g->pow2;
}

int64_t numXi(int64_t index)
{
    return (1 << ((uint64_t)index)) * (index + 1) * index;
}

void WriteId(struct Graph *g, uint8_t *Node, const int64_t id)
{
    fseek(g->db, id * NODE_SIZE, SEEK_SET);
    fwrite(Node, 1, NODE_SIZE, g->db);
}

void WriteNode(struct Graph *g, uint8_t *Node, const int64_t id)
{
    const int64_t idx = bfsToPost(g, id);
    WriteId(g, Node, idx);
}

void NewNode(struct Graph *g, const int64_t id, uint8_t *hash)
{
    WriteNode(g, hash, id);
}

uint8_t *GetId(struct Graph *g, const int64_t id)
{
    fseek(g->db, id * NODE_SIZE, SEEK_SET);
    uint8_t *node = (uint8_t *)malloc(NODE_SIZE);
    const size_t bytes_read = fread(node, 1, NODE_SIZE, g->db);
    if(bytes_read != NODE_SIZE) {
        return NULL;
    }
    return node;
}

uint8_t *GetNode(struct Graph *g, const int64_t id)
{
    const int64_t idx = bfsToPost(g, id);
    return GetId(g, idx);
}

uint32_t WriteVarInt(uint8_t *buffer, int64_t val)
{
    memset(buffer, 0, NODE_SIZE);
    uint64_t uval = ((uint64_t)(val)) << 1;
    if (val < 0)
    {
        uval = ~uval;
    }
    uint32_t i = 0;
    while (uval >= 0x80)
    {
        buffer[i] = (uint8_t)uval | 0x80;
        uval >>= 7;
        i++;
    }
    buffer[i] = (uint8_t)uval;
    return i;
}

void ButterflyGraph(struct Graph *g, int64_t index, int64_t *count)
{
    if (index == 0)
    {
        index = 1;
    }

    int64_t numLevel = 2 * index;
    int64_t perLevel = (int64_t)(1 << (uint64_t)index);
    int64_t begin = *count - perLevel;
    int64_t level, i;

    for (level = 1; level < numLevel; level++)
    {
        for (i = 0; i < perLevel; i++)
        {
            int64_t prev;
            int64_t shift = index - level;
            if (level > numLevel / 2)
            {
                shift = level - numLevel / 2;
            }
            if (((i >> (uint64_t)shift) & 1) == 0)
            {
                prev = i + (1 << (uint64_t)shift);
            }
            else
            {
                prev = i - (1 << (uint64_t)shift);
            }

            uint8_t *parent0 = GetNode(g, begin + (level - 1) * perLevel + prev);
            uint8_t *parent1 = GetNode(g, *count - perLevel);
            uint8_t *buf = (uint8_t *)malloc(NODE_SIZE);
            WriteVarInt(buf, *count);
            uint8_t *hashInput = (uint8_t *)malloc(NODE_SIZE * 4);
            memcpy(hashInput, g->pk, NODE_SIZE);
            memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
            memcpy(hashInput + (NODE_SIZE * 2), parent0, NODE_SIZE);
            memcpy(hashInput + (NODE_SIZE * 3), parent1, NODE_SIZE);

            uint8_t *hashOutput = (uint8_t *)malloc(NODE_SIZE);
            sha3(hashInput, NODE_SIZE * 4, hashOutput, NODE_SIZE);

            NewNode(g, *count, hashOutput);
            (*count)++;

            free(hashOutput);
            free(hashInput);
            free(parent0);
            free(parent1);
            free(buf);
        }
    }
}

void XiGraphIter(struct Graph *g, int64_t index)
{
    int64_t count = g->pow2;

    int8_t stackSize = 5;
    int64_t *stack = (int64_t *)malloc(sizeof(int64_t) * stackSize);
    for (int i = 0; i < 5; i++)
        stack[i] = index;

    int8_t graphStackSize = 5;
    int32_t *graphStack = (int32_t *)malloc(sizeof(int32_t) * graphStackSize);
    for (int i = 0; i < 5; i++)
        graphStack[i] = graphStackSize - i - 1;

    int64_t i = 0;
    int64_t graph = 0;
    int64_t pow2index = 1 << ((uint64_t)index);

    for (i = 0; i < pow2index; i++)
    {
        uint8_t *buf = (uint8_t *)malloc(NODE_SIZE);
        WriteVarInt(buf, count);
        uint8_t *hashInput = (uint8_t *)malloc(NODE_SIZE * 2);
        memcpy(hashInput, g->pk, NODE_SIZE);
        memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
        uint8_t *hashOutput = (uint8_t *)malloc(NODE_SIZE);

        sha3(hashInput, NODE_SIZE * 2, hashOutput, NODE_SIZE);
        NewNode(g, count, hashOutput);
        count++;

        free(hashOutput);
        free(hashInput);
        free(buf);
    }

    if (index == 1)
    {
        ButterflyGraph(g, index, &count);
        return;
    }

    while (stackSize != 0 && graphStackSize != 0)
    {

        index = stack[stackSize - 1];
        graph = graphStack[graphStackSize - 1];

        stackSize--;
        if (stackSize > 0)
        {
            int64_t *tempStack = (int64_t *)malloc(sizeof(int64_t) * (stackSize));
            memcpy(tempStack, stack, sizeof(int64_t) * (stackSize));
            free(stack);
            stack = tempStack;
        }

        graphStackSize--;
        if (graphStackSize > 0)
        {
            int32_t *tempGraphStack = (int32_t *)malloc(sizeof(int32_t) * (graphStackSize));
            memcpy(tempGraphStack, graphStack, sizeof(int32_t) * (graphStackSize));
            free(graphStack);
            graphStack = tempGraphStack;
        }

        int8_t indicesSize = 5;
        int64_t *indices = (int64_t *)malloc(sizeof(int64_t) * indicesSize);
        for (int i = 0; i < indicesSize; i++)
            indices[i] = index - 1;

        int8_t graphsSize = 5;
        int32_t *graphs = (int32_t *)malloc(sizeof(int32_t) * graphsSize);
        for (int i = 0; i < graphsSize; i++)
            graphs[i] = graphsSize - i - 1;

        int64_t pow2indexInner = 1 << ((uint64_t)index);
        int64_t pow2indexInner_1 = 1 << ((uint64_t)index - 1);

        if (graph == 0)
        {
            uint64_t sources = count - pow2indexInner;
            for (i = 0; i < pow2indexInner_1; i++)
            {
                uint8_t *parent0 = GetNode(g, sources + i);
                uint8_t *parent1 = GetNode(g, sources + i + pow2indexInner_1);

                uint8_t *buf = (uint8_t *)malloc(NODE_SIZE);
                WriteVarInt(buf, count);

                uint8_t *hashInput = (uint8_t *)malloc(NODE_SIZE * 4);
                memcpy(hashInput, g->pk, NODE_SIZE);
                memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 2), parent0, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 3), parent1, NODE_SIZE);

                uint8_t *hashOutput = (uint8_t *)malloc(NODE_SIZE);
                sha3(hashInput, NODE_SIZE * 4, hashOutput, NODE_SIZE);

                NewNode(g, count, hashOutput);
                count++;

                free(hashOutput);
                free(hashInput);
                free(parent0);
                free(parent1);
                free(buf);
            }
        }
        else if (graph == 1)
        {
            uint64_t firstXi = count;
            for (i = 0; i < pow2indexInner_1; i++)
            {
                uint64_t nodeId = firstXi + i;
                uint8_t *parent = GetNode(g, firstXi - pow2indexInner_1 + i);

                uint8_t *buf = (uint8_t *)malloc(NODE_SIZE);
                WriteVarInt(buf, nodeId);

                uint8_t *hashInput = (uint8_t *)malloc(NODE_SIZE * 3);
                memcpy(hashInput, g->pk, NODE_SIZE);
                memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 2), parent, NODE_SIZE);

                uint8_t *hashOutput = (uint8_t *)malloc(NODE_SIZE);
                sha3(hashInput, NODE_SIZE * 3, hashOutput, NODE_SIZE);

                NewNode(g, count, hashOutput);
                count++;

                free(hashOutput);
                free(hashInput);
                free(parent);
                free(buf);
            }
        }
        else if (graph == 2)
        {
            uint64_t secondXi = count;
            for (i = 0; i < pow2indexInner_1; i++)
            {
                uint64_t nodeId = secondXi + i;
                uint8_t *parent = GetNode(g, secondXi - pow2indexInner_1 + i);

                uint8_t *buf = (uint8_t *)malloc(NODE_SIZE);
                WriteVarInt(buf, nodeId);

                uint8_t *hashInput = (uint8_t *)malloc(NODE_SIZE * 3);
                memcpy(hashInput, g->pk, NODE_SIZE);
                memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 2), parent, NODE_SIZE);

                uint8_t *hashOutput = (uint8_t *)malloc(NODE_SIZE);
                sha3(hashInput, NODE_SIZE * 3, hashOutput, NODE_SIZE);

                NewNode(g, count, hashOutput);
                count++;

                free(hashOutput);
                free(hashInput);
                free(parent);
                free(buf);
            }
        }
        else if (graph == 3)
        {
            uint64_t secondButter = count;
            for (i = 0; i < pow2indexInner_1; i++)
            {
                uint64_t nodeId = secondButter + i;
                uint8_t *parent = GetNode(g, secondButter - pow2indexInner_1 + i);

                uint8_t *buf = (uint8_t *)malloc(NODE_SIZE);
                WriteVarInt(buf, nodeId);

                uint8_t *hashInput = (uint8_t *)malloc(NODE_SIZE * 3);
                memcpy(hashInput, g->pk, NODE_SIZE);
                memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 2), parent, NODE_SIZE);

                uint8_t *hashOutput = (uint8_t *)malloc(NODE_SIZE);
                sha3(hashInput, NODE_SIZE * 3, hashOutput, NODE_SIZE);

                NewNode(g, count, hashOutput);
                count++;

                free(hashOutput);
                free(hashInput);
                free(parent);
                free(buf);
            }
        }
        else
        {
            uint64_t sinks = count;
            uint64_t sources = sinks + pow2indexInner - numXi(index);
            for (i = 0; i < pow2indexInner_1; i++)
            {
                uint64_t nodeId0 = sinks + i;
                uint64_t nodeId1 = sinks + i + pow2indexInner_1;
                uint8_t *parent0 = GetNode(g, sinks - pow2indexInner_1 + i);
                uint8_t *parent1_0 = GetNode(g, sources + i);
                uint8_t *parent1_1 = GetNode(g, sources + i + pow2indexInner_1);

                uint8_t *buf = (uint8_t *)malloc(NODE_SIZE);
                WriteVarInt(buf, nodeId0);

                uint8_t *hashInput = (uint8_t *)malloc(NODE_SIZE * 4);
                memcpy(hashInput, g->pk, NODE_SIZE);
                memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 2), parent0, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 3), parent1_0, NODE_SIZE);

                uint8_t *hashOutput0 = (uint8_t *)malloc(NODE_SIZE);
                sha3(hashInput, NODE_SIZE * 4, hashOutput0, NODE_SIZE);

                WriteVarInt(buf, nodeId1);

                memcpy(hashInput, g->pk, NODE_SIZE);
                memcpy(hashInput + NODE_SIZE, buf, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 2), parent0, NODE_SIZE);
                memcpy(hashInput + (NODE_SIZE * 3), parent1_1, NODE_SIZE);

                uint8_t *hashOutput1 = (uint8_t *)malloc(NODE_SIZE);
                sha3(hashInput, NODE_SIZE * 4, hashOutput1, NODE_SIZE);

                NewNode(g, nodeId0, hashOutput0);
                NewNode(g, nodeId1, hashOutput1);
                count += 2;

                free(parent0);
                free(parent1_0);
                free(parent1_1);
                free(buf);
                free(hashInput);
                free(hashOutput0);
                free(hashOutput1);
            }
        }

        if ((graph == 0 || graph == 3) ||
            ((graph == 1 || graph == 2) && index == 2))
        {
            ButterflyGraph(g, index - 1, &count);
        }
        else if (graph == 1 || graph == 2)
        {

            int64_t *tempStack = (int64_t *)malloc(sizeof(int64_t) * (stackSize + indicesSize));
            memcpy(tempStack, stack, stackSize * sizeof(int64_t));
            memcpy(tempStack + stackSize, indices, indicesSize * sizeof(int64_t));
            stackSize += indicesSize;
            free(stack);
            stack = tempStack;

            int32_t *tempGraphStack = (int32_t *)malloc(sizeof(int32_t) * (graphStackSize + graphsSize));
            memcpy(tempGraphStack, graphStack, graphStackSize * sizeof(int32_t));
            memcpy(tempGraphStack + graphStackSize, graphs, graphsSize * sizeof(int32_t));
            graphStackSize += graphsSize;
            free(graphStack);
            graphStack = tempGraphStack;
        }

        free(indices);
        free(graphs);
    }

    free(stack);
    free(graphStack);
}

struct Graph *NewGraph(int64_t index, const char* targetFile, uint8_t *pk)
{
    uint8_t exists = 0;
    FILE *db;
    if ((db = fopen_utf8(targetFile, "r")) != NULL)
    {
        fclose(db);
        exists = 1;
    }

    db = fopen_utf8(targetFile, "wb+");
    int64_t size = numXi(index);
    int64_t log2 = Log2(size) + 1;
    int64_t pow2 = 1 << ((uint64_t)log2);

    struct Graph *g = (struct Graph *)malloc(sizeof(struct Graph));

    if ( !g ) return NULL;

    g->db = db;
    g->log2 = log2;
    g->pow2 = pow2;
    g->pk = pk;
    g->index = index;

    if (exists == 0)
    {
        XiGraphIter(g, index);
    }

    fclose(db);
    return g;
}

//-----------------------------------------------------------------------------

// use info for _mm_malloc, then verify file
int verthash_generate_data_file(const char* output_file_name)
{
    const char *hashInput = "Verthash Proof-of-Space Datafile";
    uint8_t *pk = (uint8_t*)malloc( NODE_SIZE );
    
    if ( !pk )
    {
      applog( LOG_ERR, "Verthash data memory allocation failed");
      return -1;
    }

    sha3( hashInput, 32, pk, NODE_SIZE );

    int64_t index = 17;
    if ( !NewGraph( index, output_file_name, pk ) )
    {
       applog( LOG_ERR, "Verthash file creation failed");
       return -1;
    }

    return 0;
}

